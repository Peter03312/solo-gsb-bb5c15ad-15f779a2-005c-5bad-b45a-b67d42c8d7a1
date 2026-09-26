/**
 * 无损精简模糊对照：在缩小的报文空间（10.1.0.0/24 × 端口 0..63 × TCP/UDP）
 * 上逐报文暴力首命中，并对每条有有效流量的规则暴力模拟删除（从规则列表
 * 移除该规则后重新逐报文求首命中），与 analyzeSimplify 的安全判定、
 * 接管 / 冲突分组大小及代表报文逐一对照。
 */
import assert from 'node:assert'
import { analyzeSimplify } from './audit/simplify'
import { validateRules } from './audit/engine'
import { ipv4ToInt } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

function randomCidr(): string {
  const hostBits = rand(5) // /24 .. /28
  const prefix = 24 + hostBits
  const size = 2 ** hostBits
  const base = rand(256 / size) * size
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `z${i}`,
    name: `R${i}`,
    cidr: randomCidr(),
    portStart: String(rand(64)),
    portEnd: String(63),
    protocol: PROTOS[rand(3)],
    action: ACTIONS[rand(2)],
    enabled: true,
  })).map((r) =>
    Number(r.portStart) > Number(r.portEnd)
      ? { ...r, portStart: r.portEnd, portEnd: String(rand(64)) }
      : r,
  )
}

const ALL_PACKETS: Array<{ ip: number; port: number; proto: number; name: string }> = []
for (let ip = 0; ip < 256; ip++) {
  for (let port = 0; port < 64; port++) {
    for (let proto = 0; proto < 2; proto++) {
      ALL_PACKETS.push({
        ip: ipv4ToInt(`10.1.0.${ip}`),
        port,
        proto,
        name: proto === 0 ? 'TCP' : 'UDP',
      })
    }
  }
}

/** 在给定规则子集上逐报文求首命中规则下标（-1 = 未命中） */
function bruteOwners(rules: ReturnType<typeof validateRules>['valid']) {
  return ALL_PACKETS.map((pkt) => {
    for (let pos = 0; pos < rules.length; pos++) {
      const r = rules[pos]
      if (
        pkt.ip >= r.ipStart &&
        pkt.ip <= r.ipEnd &&
        pkt.port >= r.portStart &&
        pkt.port <= r.portEnd &&
        (r.protocol === 'ANY' || r.protocol === pkt.name)
      ) {
        return pos
      }
    }
    return -1
  })
}

let rounds = 0
for (let round = 0; round < 400; round++) {
  const rules = makeRules(1 + rand(8))
  const { valid } = validateRules(rules)
  const owners = bruteOwners(valid)

  // pos -> 其首命中报文下标
  const ownedBy = new Map<number, number[]>()
  owners.forEach((pos, pi) => {
    if (pos === -1) return
    const list = ownedBy.get(pos)
    if (list) list.push(pi)
    else ownedBy.set(pos, [pi])
  })

  const result = analyzeSimplify(rules)
  const candById = new Map(
    result.items
      .filter((i) => i.kind === 'candidate')
      .map((i) => [i.ruleId, i] as const),
  )

  let analyzed = 0
  for (let pos = 0; pos < valid.length; pos++) {
    const owned = ownedBy.get(pos)
    if (!owned) {
      // 无有效流量：引擎必须跳过而不是给出候选
      assert.ok(!candById.has(valid[pos].id), `round ${round}: shadowed rule got candidate`)
      continue
    }
    analyzed++
    const cand = candById.get(valid[pos].id)
    assert.ok(cand, `round ${round}: active rule ${valid[pos].name} missing candidate`)
    if (!cand || cand.kind !== 'candidate') continue

    // 有效流量计数（逐报文）与引擎大小一致
    assert.equal(cand.effectiveSize, owned.length,
      `round ${round} rule ${valid[pos].name}: effectiveSize`)
    assert.ok(cand.effectiveCells <= owned.length)

    // 暴力模拟删除：移除该规则后重新逐报文首命中
    const remaining = valid.filter((_, q) => q !== pos)
    const newOwners = bruteOwners(remaining)

    let bruteSafe = true
    const bruteGroups = new Map<string, number>() // `take:<id>` / unmatched
    for (const pi of owned) {
      const newPos = newOwners[pi]
      if (newPos === -1) {
        bruteSafe = false
        bruteGroups.set('unmatched', (bruteGroups.get('unmatched') ?? 0) + 1)
      } else {
        const nr = remaining[newPos]
        const sameAction = nr.action === valid[pos].action
        if (!sameAction) bruteSafe = false
        const tag = `${sameAction ? 'take' : 'conf'}:${nr.id}`
        bruteGroups.set(tag, (bruteGroups.get(tag) ?? 0) + 1)
      }
    }
    assert.equal(cand.safe, bruteSafe,
      `round ${round} rule ${valid[pos].name}: safe mismatch; rules=${JSON.stringify(rules)}`)

    // 各接管 / 冲突组大小与暴力计数一致
    for (const g of cand.takeovers) {
      assert.equal(g.size, bruteGroups.get(`take:${g.ruleId}`) ?? 0,
        `round ${round}: takeover size ${g.ruleName}`)
    }
    for (const c of cand.conflicts) {
      const tag = c.kind === 'unmatched' ? 'unmatched' : `conf:${c.ruleId}`
      assert.equal(c.size, bruteGroups.get(tag) ?? 0,
        `round ${round}: conflict size ${tag}`)
    }
    // 区域行大小合计与分组大小一致（精确区域逐行展开）
    for (const g of cand.takeovers) {
      const rowSum = g.regions.reduce(
        (s, reg) => s + reg.rows.reduce((t, r) => t + r.size, 0),
        0,
      )
      assert.equal(rowSum, g.size)
    }
    for (const c of cand.conflicts) {
      const rowSum = c.regions.reduce(
        (s, reg) => s + reg.rows.reduce((t, r) => t + r.size, 0),
        0,
      )
      assert.equal(rowSum, c.size)
    }

    // 代表报文可复现：删除后必须命中所述接管规则，或确实未命中
    const checkPacket = (
      p: { srcIp: string; srcPort: number; protocol: string },
      expectedId: string | null,
    ) => {
      const ip = ipv4ToInt(p.srcIp)
      const hit = remaining.find(
        (r) =>
          ip >= r.ipStart &&
          ip <= r.ipEnd &&
          p.srcPort >= r.portStart &&
          p.srcPort <= r.portEnd &&
          (r.protocol === 'ANY' || r.protocol === p.protocol),
      )
      if (expectedId === null) assert.equal(hit, undefined)
      else assert.equal(hit?.id, expectedId)
    }
    for (const g of cand.takeovers) checkPacket(g.packet, g.ruleId)
    for (const c of cand.conflicts) checkPacket(c.packet, c.ruleId)
  }

  assert.equal(result.analyzedCount, analyzed)
  rounds++
}
console.log(`无损精简模糊对照 ${rounds} 轮全部通过 ✔`)
