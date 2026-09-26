/**
 * 策略目标验证的模糊对照测试：在缩小的报文空间（IP 取 /24 内 256 个地址，
 * 端口取 0..63，协议 TCP/UDP）上，用逐报文暴力首命中对 verifyGoal 的
 * 分类大小、逐协议统计、精确区域（展开后逐报文比对）与代表报文逐项对照。
 */
import assert from 'node:assert'
import { validateRules } from './audit/engine'
import { verifyGoal } from './audit/verify'
import type { RuleInput } from './audit/types'
import { ipv4ToInt, parseCidrStrict } from './audit/iputil'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

/** 受限空间内的规范 CIDR：10.1.0.0/24 内、/24../28 对齐（保证主机位为零） */
function randomCidr(): string {
  const prefix = 24 + rand(5) // /24 .. /28
  const blockSize = 2 ** (32 - prefix)
  const base = rand(256 / blockSize) * blockSize
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const bad = rand(6) === 0 // 约 1/6 概率产生非法规则，检验排除语义
    const a = rand(64)
    const b = a + rand(64 - a)
    return {
      id: `f${i}`,
      name: `R${i}`,
      cidr: bad && rand(2) === 0 ? '10.1.0.5/24' : randomCidr(),
      portStart: String(bad && rand(2) === 0 ? 99999 : a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(2)],
      enabled: true,
    }
  })
}

function randomGoal() {
  const a = rand(64)
  const b = a + rand(64 - a)
  return {
    cidr: randomCidr(),
    portStart: String(a),
    portEnd: String(b),
    protocol: PROTOS[rand(3)],
    expectedAction: ACTIONS[rand(2)],
  }
}

function firstHit(
  valid: ReturnType<typeof validateRules>['valid'],
  ip: number,
  port: number,
  proto: string,
) {
  return valid.find(
    (r) =>
      ip >= r.ipStart &&
      ip <= r.ipEnd &&
      port >= r.portStart &&
      port <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === proto),
  )
}

/** 把精确区域（协议 → 端口段 × CIDR 行）展开成 `ip,port,proto` 单元集合 */
function expandRegions(
  regions: Array<{
    protocol: string
    rows: Array<{ portStart: number; portEnd: number; cidrs: string[] }>
  }>,
): Set<string> {
  const covered = new Set<string>()
  for (const reg of regions) {
    for (const row of reg.rows) {
      for (const cidr of row.cidrs) {
        const pc = parseCidrStrict(cidr)
        for (let ip = pc.start; ip <= pc.end; ip++) {
          for (let port = row.portStart; port <= row.portEnd; port++) {
            covered.add(`${ip},${port},${reg.protocol}`)
          }
        }
      }
    }
  }
  return covered
}

function assertSameCells(actual: Set<string>, expected: Set<string>, what: string) {
  assert.equal(actual.size, expected.size, `${what}：单元数不一致`)
  for (const cell of expected) {
    assert.ok(actual.has(cell), `${what}：缺少单元 ${cell}`)
  }
}

const ROUNDS = 300
for (let round = 0; round < ROUNDS; round++) {
  const rules = makeRules(1 + rand(8))
  const goal = randomGoal()
  const out = verifyGoal(rules, goal)
  assert.equal(out.ok, true, `round ${round} 目标应合法`)
  if (!out.ok) continue
  const r = out.result
  const { valid, invalid } = validateRules(rules)
  const g = parseCidrStrict(goal.cidr)
  const protos = goal.protocol === 'ANY' ? ['TCP', 'UDP'] : [goal.protocol]
  const pStart = Number(goal.portStart)
  const pEnd = Number(goal.portEnd)

  // 逐报文暴力首命中分类
  let conform = 0
  let other = 0
  let unmatched = 0
  const otherByAction = new Map<string, number>()
  const perProto: Record<string, { c: number; o: number; u: number }> = {
    TCP: { c: 0, o: 0, u: 0 },
    UDP: { c: 0, o: 0, u: 0 },
  }
  const cellsByGroup = new Map<string, Set<string>>()
  const addCell = (key: string, cell: string) => {
    let set = cellsByGroup.get(key)
    if (!set) {
      set = new Set()
      cellsByGroup.set(key, set)
    }
    set.add(cell)
  }
  for (let ip = g.start; ip <= g.end; ip++) {
    for (let port = pStart; port <= pEnd; port++) {
      for (const proto of protos) {
        const hit = firstHit(valid, ip, port, proto)
        const cell = `${ip},${port},${proto}`
        if (!hit) {
          unmatched++
          perProto[proto].u++
          addCell('#u', cell)
        } else if (hit.action === goal.expectedAction) {
          conform++
          perProto[proto].c++
        } else {
          other++
          otherByAction.set(hit.action, (otherByAction.get(hit.action) ?? 0) + 1)
          perProto[proto].o++
          addCell(`a:${hit.action}`, cell)
        }
      }
    }
  }

  const ctx = `round ${round} goal=${JSON.stringify(goal)}`
  assert.equal(r.conformSize, conform, `${ctx} conform`)
  assert.equal(r.otherActionSize, other, `${ctx} other`)
  assert.equal(r.unmatchedSize, unmatched, `${ctx} unmatched`)
  assert.equal(r.totalSize, conform + other + unmatched, `${ctx} total`)
  assert.equal(r.invalidExcluded, invalid.length, `${ctx} invalidExcluded`)
  for (const p of r.perProtocol) {
    assert.equal(p.conformSize, perProto[p.protocol].c, `${ctx} ${p.protocol} conform`)
    assert.equal(p.otherActionSize, perProto[p.protocol].o, `${ctx} ${p.protocol} other`)
    assert.equal(p.unmatchedSize, perProto[p.protocol].u, `${ctx} ${p.protocol} unmatched`)
  }

  // 违规分组：大小、精确区域（展开逐报文比对）、代表报文
  assert.equal(r.actionGroups.length, otherByAction.size, `${ctx} 分组数`)
  for (const grp of r.actionGroups) {
    assert.equal(grp.size, otherByAction.get(grp.action), `${ctx} 组 ${grp.action} 大小`)
    assert.equal(
      grp.regions.reduce((s, x) => s + x.size, 0),
      grp.size,
      `${ctx} 组 ${grp.action} 区域合计`,
    )
    assertSameCells(
      expandRegions(grp.regions),
      cellsByGroup.get(`a:${grp.action}`) ?? new Set(),
      `${ctx} 组 ${grp.action} 区域`,
    )
    for (const ex of grp.examples) {
      const ipN = ipv4ToInt(ex.srcIp)
      assert.ok(ipN >= g.start && ipN <= g.end, `${ctx} 代表报文 IP 在目标内`)
      assert.ok(ex.srcPort >= pStart && ex.srcPort <= pEnd, `${ctx} 代表报文端口在目标内`)
      const hit = firstHit(valid, ipN, ex.srcPort, ex.protocol)
      assert.ok(hit, `${ctx} 代表报文应命中某条规则`)
      assert.equal(hit!.action, grp.action, `${ctx} 代表报文动作`)
      assert.equal(hit!.index, ex.matchedRuleIndex, `${ctx} 代表报文命中规则序号`)
    }
  }

  // 未命中分类：区域与代表报文
  if (unmatched === 0) {
    assert.equal(r.unmatched, null, `${ctx} 无未命中`)
  } else {
    assert.ok(r.unmatched, `${ctx} 应有未命中分组`)
    assert.equal(r.unmatched!.size, unmatched, `${ctx} 未命中大小`)
    assertSameCells(
      expandRegions(r.unmatched!.regions),
      cellsByGroup.get('#u') ?? new Set(),
      `${ctx} 未命中区域`,
    )
    for (const ex of r.unmatched!.examples) {
      const hit = firstHit(valid, ipv4ToInt(ex.srcIp), ex.srcPort, ex.protocol)
      assert.equal(hit, undefined, `${ctx} 未命中代表报文不应命中任何规则`)
    }
  }
}

console.log(`目标验证模糊对照 ${ROUNDS} 轮全部通过 ✔`)
