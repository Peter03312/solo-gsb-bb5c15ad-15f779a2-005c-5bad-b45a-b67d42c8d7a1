/**
 * 模糊对照测试：审计例外豁免。
 * 在缩小报文空间（10.1.0.0/24 × 端口 0..63 × TCP/UDP）上：
 *   1. 随机生成规则集，逐报文暴力首命中，得出每条规则的「被遮蔽报文集合」；
 *   2. 随机生成例外清单（合法、未过期、问题类型按该规则的实际状态给）；
 *   3. 逐报文判定它是否被任一适用例外覆盖（与遮蔽集合做精确交集）；
 *   4. 对照引擎 evaluateExceptions 的 exemptSize / pendingSize / 覆盖大小。
 */
import assert from 'node:assert'
import { validateRules } from './audit/engine'
import { evaluateExceptions } from './audit/exemption'
import type { ExceptionInput, RuleInput } from './audit/types'
import { ipv4ToInt } from './audit/iputil'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

/**
 * 把随机块表示成规范 CIDR（限定 10.1.0.0/24 内）。
 * extra = 超出 /24 的额外前缀位数（0=整 /24，1..4=/25../28），
 * 块大小（IP 数）= 2^(8-extra)，块起始为其整数倍。
 */
function randomCidr(): string {
  const extra = rand(5)
  const prefix = 24 + extra
  const size = 2 ** (8 - extra)
  const base = rand(256 / size) * size
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const start = rand(64)
    return {
      id: `f${i}`,
      name: `R${i}`,
      cidr: randomCidr(),
      portStart: String(start),
      portEnd: String(Math.min(63, start + rand(64))),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(2)],
      enabled: true,
    }
  })
}

interface BruteRule {
  blocked: Set<string>
  owned: number
  declared: number
  status: 'reachable' | 'partial-shadowed' | 'fully-shadowed'
}

function bruteForce(rules: RuleInput[]): BruteRule[] {
  const { valid } = validateRules(rules)
  const out: BruteRule[] = valid.map(() => ({
    blocked: new Set<string>(),
    owned: 0,
    declared: 0,
    status: 'reachable',
  }))
  for (let ip = 0; ip < 256; ip++) {
    const ipNum = ipv4ToInt(`10.1.0.${ip}`)
    for (let port = 0; port < 64; port++) {
      for (let proto = 0; proto < 2; proto++) {
        const pName = proto === 0 ? 'TCP' : 'UDP'
        let first = -1
        const declares: number[] = []
        for (let pos = 0; pos < valid.length; pos++) {
          const r = valid[pos]
          const ipOk = ipNum >= r.ipStart && ipNum <= r.ipEnd
          const portOk = port >= r.portStart && port <= r.portEnd
          const protoOk = r.protocol === 'ANY' || r.protocol === pName
          if (ipOk && portOk && protoOk) {
            declares.push(pos)
            if (first === -1) first = pos
          }
        }
        for (const pos of declares) {
          out[pos].declared++
          if (first === pos) out[pos].owned++
          else if (first !== -1) out[pos].blocked.add(`${ip}.${port}.${proto}`)
        }
      }
    }
  }
  for (const b of out) {
    if (b.blocked.size === 0) b.status = 'reachable'
    else if (b.owned === 0) b.status = 'fully-shadowed'
    else b.status = 'partial-shadowed'
  }
  return out
}

const ROUNDS = 400
const NOW = new Date('2026-06-01T00:00:00Z')

for (let round = 0; round < ROUNDS; round++) {
  const n = 2 + rand(6)
  const rules = makeRules(n)
  const { valid } = validateRules(rules)
  const brute = bruteForce(rules)

  // 为每个有遮蔽区域的规则以一定概率生成 0..3 条随机例外（未过期、问题类型匹配）
  const exceptions: ExceptionInput[] = []
  const expectedCovered: Array<Set<string>[]> = [] // 每规则 -> 各条例外的报文集合
  valid.forEach((r, pos) => {
    const b = brute[pos]
    if (b.status === 'reachable') return
    const list: Set<string>[] = []
    const count = rand(4)
    for (let k = 0; k < count; k++) {
      const issueType = b.status
      const cidr = randomCidr()
      const ps = rand(64)
      const pe = Math.min(63, ps + rand(64))
      const protocol = PROTOS[rand(3)]
      const id = `e${round}-${pos}-${k}`
      exceptions.push({
        id,
        ruleId: r.id,
        issueType,
        cidr,
        portStart: String(ps),
        portEnd: String(pe),
        protocol,
        expiresAt: '2030-01-01T00:00:00Z',
        notes: 'fuzz',
      })
      // 暴力计算该例外与遮蔽集合的交集
      const covered = new Set<string>()
      for (const key of b.blocked) {
        const [ipS, portS, protoS] = key.split('.')
        const ip = Number(ipS)
        const port = Number(portS)
        const proto = Number(protoS)
        const ipNum = ipv4ToInt(`10.1.0.${ip}`)
        const { start, end } = (() => {
          // 重新解析 CIDR
          const parts = cidr.split('/')
          const prefix = Number(parts[1])
          const baseIp = ipv4ToInt(parts[0])
          const size = 2 ** (32 - prefix)
          return { start: baseIp, end: baseIp + size - 1 }
        })()
        const protoName = proto === 0 ? 'TCP' : 'UDP'
        const protoOk = protocol === 'ANY' || protocol === protoName
        if (ipNum >= start && ipNum <= end && port >= ps && port <= pe && protoOk) {
          covered.add(key)
        }
      }
      list.push(covered)
    }
    expectedCovered[pos] = list
  })

  const report = evaluateExceptions(rules, exceptions, NOW)

  // 所有未过期合法例外都应是 active（问题类型均按实际状态给出）
  assert.equal(
    report.stats.invalidCount + report.stats.expiredCount + report.stats.targetBadCount +
      report.stats.mismatchCount,
    0,
    `round ${round}: 不应有失效例外`,
  )

  valid.forEach((r, pos) => {
    const b = brute[pos]
    if (b.status === 'reachable') return
    const entry = report.entries.find(
      (e) => e.kind === 'rule' && e.ruleId === r.id,
    )
    if (!entry || entry.kind !== 'rule') throw new Error(`round ${round}: 缺少规则条目`)
    const list = expectedCovered[pos] ?? []
    const union = new Set<string>()
    list.forEach((s) => s.forEach((k) => union.add(k)))
    // 引擎「单元」是被异常边界进一步切分的粗粒度原子块（一个单元可覆盖多个
    // 离散报文），因此单元数与逐报文数不可直接比较；报文空间大小（每个离散
    // 报文计 1）才可与暴力计数对照。
    assert.equal(entry.blockedSize, b.blocked.size, `round ${round} ${r.id}: blockedSize`)
    assert.equal(entry.exemptSize, union.size, `round ${round} ${r.id}: exemptSize`)
    assert.equal(
      entry.pendingSize,
      b.blocked.size - union.size,
      `round ${round} ${r.id}: pendingSize`,
    )
    assert.equal(
      entry.fullyExempt,
      union.size === b.blocked.size,
      `round ${round} ${r.id}: fullyExempt`,
    )
  })

  // 逐条例外覆盖大小对照（按 exceptionId）
  const coverageById = new Map<string, number>()
  for (const e of report.entries) {
    if (e.kind !== 'rule') continue
    for (const c of e.coverages) coverageById.set(c.exceptionId, c.coveredSize)
  }
  valid.forEach((r, pos) => {
    const list = expectedCovered[pos] ?? []
    const ids = exceptions.filter((e) => e.ruleId === r.id).map((e) => e.id)
    list.forEach((covered, k) => {
      assert.equal(
        coverageById.get(ids[k]),
        covered.size,
        `round ${round}: 例外 ${ids[k]} 覆盖报文数`,
      )
    })
  })

  // 代表报文必须真的落在已豁免 / 待处理报文集合中（可复现性）
  for (const e of report.entries) {
    if (e.kind !== 'rule') continue
    const pos = valid.findIndex((r) => r.id === e.ruleId)
    const keyOf = (p: { srcIp: string; srcPort: number; protocol: string }) => {
      const octets = p.srcIp.split('.').map(Number)
      return `${octets[3]}.${p.srcPort}.${p.protocol === 'TCP' ? 0 : 1}`
    }
    const union = new Set<string>()
    ;(expectedCovered[pos] ?? []).forEach((s) => s.forEach((k) => union.add(k)))
    if (e.exemptRepresentative) {
      assert.ok(
        union.has(keyOf(e.exemptRepresentative)),
        `round ${round}: 已豁免代表报文必须在豁免集合内`,
      )
    }
    if (e.pendingRepresentative) {
      assert.ok(
        brute[pos].blocked.has(keyOf(e.pendingRepresentative)) &&
          !union.has(keyOf(e.pendingRepresentative)),
        `round ${round}: 待处理代表报文必须在遮蔽集合且不在豁免集合内`,
      )
    }
  }
}

console.log(`审计例外模糊对照 ${ROUNDS} 轮全部通过 ✔`)
