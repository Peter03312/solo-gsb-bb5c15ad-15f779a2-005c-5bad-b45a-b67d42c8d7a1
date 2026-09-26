/**
 * 双级串联策略模糊对照：在缩小且完全可枚举的报文空间（10.1.2.0/24 × 端口 0..31
 * × {TCP, UDP}）上随机生成两阶段规则集、放行动作列表与目标，逐报文暴力执行
 * 串联首命中（一阶段未命中或动作不放行即阻断且不进入二阶段；二阶段同理；
 * 报文不改写），与 analyzeTandem 的三类大小、轨迹分组大小、精确区域逐报文
 * 覆盖、代表报文轨迹与分协议统计逐一对账。
 * 规则 CIDR 全部在 /24 内对齐、端口均在 0..31 内，因此每个枚举报文代表
 * 1 条真实报文空间，引擎大小与枚举计数精确相等。
 */
import assert from 'node:assert'
import { analyzeTandem, validateTandemTarget } from './audit/tandem'
import type { TandemCategory } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

const BASE = parseCidrStrict('10.1.2.0/24').start
const MAX_PORT = 31
const PROTOS = ['TCP', 'UDP', 'ANY'] as const
const ACTIONS = ['allow', 'deny', 'drop'] as const

/** /24 内对齐的随机 CIDR，前缀 24..28；偶发非法（主机位非零） */
function randomCidr() {
  if (rand(10) === 0) return '10.1.2.3/24' // 非法：主机位非零
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const count = 256 / size
  const start = (BASE + rand(count) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}

function makeRules(tag: string): RuleInput[] {
  const n = rand(7)
  return Array.from({ length: n }, (_, i) => {
    const a = rand(MAX_PORT + 1)
    const b = a + rand(MAX_PORT + 1 - a)
    return {
      id: `${tag}${i}`,
      name: `${tag}${i}`,
      cidr: randomCidr(),
      portStart: String(a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(3)],
      enabled: rand(8) !== 0, // 偶发停用
    }
  })
}

/** 随机非空放行动作列表（动作池的非空子集，可能含规则中不存在的动作） */
function makeAllowList(): string[] {
  const pool = [...ACTIONS, 'permit']
  const out: string[] = []
  for (const a of pool) if (rand(2) === 0) out.push(a)
  return out.length > 0 ? out : ['allow']
}

function makeTarget() {
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const start = (BASE + rand(256 / size) * size) >>> 0
  const a = rand(MAX_PORT + 1)
  const b = a + rand(MAX_PORT + 1 - a)
  return {
    cidr: `${intToIpv4(start)}/${prefix}`,
    portStart: String(a),
    portEnd: String(b),
    protocol: PROTOS[rand(3)],
  }
}

interface Hit {
  name: string
  action: string
}

function firstHit(
  valid: ReturnType<typeof validateRules>['valid'],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
): Hit | null {
  const active = valid.filter((r) => r.enabled)
  const r = active.find(
    (rule) =>
      ip >= rule.ipStart &&
      ip <= rule.ipEnd &&
      port >= rule.portStart &&
      port <= rule.portEnd &&
      (rule.protocol === 'ANY' || rule.protocol === proto),
  )
  return r ? { name: r.name, action: r.action } : null
}

interface Trace {
  category: TandemCategory
  s1: string | null // 第一阶段首命中规则名；null = 未命中
  entered: boolean
  s2: string | null // 第二阶段首命中规则名；null = 未命中 / 未进入
}

function bruteTrace(
  valid1: ReturnType<typeof validateRules>['valid'],
  valid2: ReturnType<typeof validateRules>['valid'],
  allow1: string[],
  allow2: string[],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
): Trace {
  const h1 = firstHit(valid1, ip, port, proto)
  if (!h1 || !allow1.includes(h1.action)) {
    return { category: 'blocked-stage1', s1: h1?.name ?? null, entered: false, s2: null }
  }
  const h2 = firstHit(valid2, ip, port, proto)
  if (!h2 || !allow2.includes(h2.action)) {
    return { category: 'blocked-stage2', s1: h1.name, entered: true, s2: h2?.name ?? null }
  }
  return { category: 'pass', s1: h1.name, entered: true, s2: h2.name }
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const rules1 = makeRules('A')
  const rules2 = makeRules('B')
  const allow1 = makeAllowList()
  const allow2 = makeAllowList()
  const targetInput = makeTarget()
  const { valid: valid1 } = validateRules(rules1)
  const { valid: valid2 } = validateRules(rules2)
  const { target, errors } = validateTandemTarget(targetInput)
  assert.equal(errors.length, 0)
  const result = analyzeTandem(rules1, rules2, allow1, allow2, target!)

  // 暴力逐报文串联重放
  const catCount: Record<TandemCategory, number> = {
    pass: 0,
    'blocked-stage1': 0,
    'blocked-stage2': 0,
  }
  const groupCount = new Map<string, number>()
  const catPackets = new Map<TandemCategory, Array<{ ip: number; port: number; proto: 'TCP' | 'UDP' }>>()
  const perProto = {
    TCP: { pass: 0, b1: 0, b2: 0 },
    UDP: { pass: 0, b1: 0, b2: 0 },
  }
  for (const c of Object.keys(catCount) as TandemCategory[]) catPackets.set(c, [])

  const targetStart = target!.ipStart
  const targetEnd = target!.ipEnd
  const protos: Array<'TCP' | 'UDP'> =
    target!.protocol === 'ANY' ? ['TCP', 'UDP'] : [target!.protocol as 'TCP' | 'UDP']
  for (let ip = targetStart; ip <= targetEnd; ip++) {
    for (let port = target!.portStart; port <= target!.portEnd; port++) {
      for (const proto of protos) {
        const t = bruteTrace(valid1, valid2, allow1, allow2, ip, port, proto)
        catCount[t.category]++
        catPackets.get(t.category)!.push({ ip, port, proto })
        const key = `${t.category}|${t.s1 ?? '∅'}|${t.entered ? t.s2 ?? '∅' : '—'}`
        groupCount.set(key, (groupCount.get(key) ?? 0) + 1)
        const pp = perProto[proto]
        if (t.category === 'pass') pp.pass++
        else if (t.category === 'blocked-stage1') pp.b1++
        else pp.b2++
      }
    }
  }

  const dump = `A=${JSON.stringify(rules1)} B=${JSON.stringify(rules2)} allow1=${allow1} allow2=${allow2} target=${JSON.stringify(targetInput)}`

  // 类别大小对账（每个枚举报文恰为 1 条报文空间）
  for (const cat of Object.keys(catCount) as TandemCategory[]) {
    assert.equal(
      result.categories[cat].size,
      catCount[cat],
      `round ${round} ${cat}: engine ${result.categories[cat].size} vs brute ${catCount[cat]}; ${dump}`,
    )
    assert.equal(
      result.categories[cat].regions.reduce((s, r) => s + r.size, 0),
      catCount[cat],
      `round ${round} ${cat}: 区域行合计不符; ${dump}`,
    )
  }
  assert.equal(
    result.totalSize,
    catCount.pass + catCount['blocked-stage1'] + catCount['blocked-stage2'],
  )

  // 分协议统计对账
  for (const p of result.perProtocol) {
    const brute = perProto[p.protocol]
    assert.equal(p.passSize, brute.pass, `round ${round} ${p.protocol} pass; ${dump}`)
    assert.equal(p.blockedStage1Size, brute.b1, `round ${round} ${p.protocol} b1; ${dump}`)
    assert.equal(p.blockedStage2Size, brute.b2, `round ${round} ${p.protocol} b2; ${dump}`)
  }

  // 轨迹分组对账：暴力分组与引擎分组一一对应（按 类别|一阶段名|二阶段名）
  for (const cat of Object.keys(catCount) as TandemCategory[]) {
    const expected = [...groupCount.keys()].filter((k) => k.startsWith(`${cat}|`))
    assert.equal(
      result.categories[cat].groups.length,
      expected.length,
      `round ${round} ${cat}: 分组数不符 engine=${result.categories[cat].groups.length} brute=${expected.length}; ${dump}`,
    )
  }
  for (const [key, count] of groupCount) {
    const [catRaw, s1, s2] = key.split('|')
    const cat = catRaw as TandemCategory
    const g = result.categories[cat].groups.find(
      (x) =>
        (x.stage1?.name ?? null) === (s1 === '∅' ? null : s1) &&
        (x.stage2?.name ?? null) === (s2 === '∅' || s2 === '—' ? null : s2),
    )
    assert.ok(g, `round ${round}: 缺少轨迹分组 ${key}; ${dump}`)
    assert.equal(g!.size, count, `round ${round}: 分组 ${key} 大小不符; ${dump}`)
  }

  // 精确区域恰好覆盖暴力分类到的报文（逐报文成员判定）
  for (const cat of Object.keys(catCount) as TandemCategory[]) {
    const packets = catPackets.get(cat)!
    let inRegion = 0
    for (const pkt of packets) {
      const reg = result.categories[cat].regions.find((r) => r.protocol === pkt.proto)
      const hitRow = reg?.rows.some(
        (row) =>
          pkt.port >= row.portStart &&
          pkt.port <= row.portEnd &&
          row.cidrs.some((c) => {
            const b = parseCidrStrict(c)
            return pkt.ip >= b.start && pkt.ip <= b.end
          }),
      )
      if (hitRow) inRegion++
    }
    assert.equal(
      inRegion,
      packets.length,
      `round ${round} ${cat}: 区域覆盖 ${inRegion}/${packets.length}; ${dump}`,
    )
  }

  // 每个轨迹分组的代表报文暴力重放，轨迹与分组一致
  for (const cat of Object.keys(catCount) as TandemCategory[]) {
    for (const g of result.categories[cat].groups) {
      const p = g.packet
      const ip = parseCidrStrict(`${p.srcIp}/32`).start
      const t = bruteTrace(valid1, valid2, allow1, allow2, ip, p.srcPort, p.protocol)
      assert.equal(t.category, g.category, `round ${round}: 代表报文类别不符; ${dump}`)
      assert.equal(t.s1, g.stage1?.name ?? null)
      assert.equal(t.entered, g.enteredStage2)
      assert.equal(t.s2, g.stage2?.name ?? null)
    }
    // 类别代表报文轨迹与类别一致
    for (const p of result.categories[cat].examples) {
      const ip = parseCidrStrict(`${p.srcIp}/32`).start
      const t = bruteTrace(valid1, valid2, allow1, allow2, ip, p.srcPort, p.protocol)
      assert.equal(t.category, cat)
      assert.equal(t.s1, p.stage1?.name ?? null)
      assert.equal(t.entered, p.enteredStage2)
      assert.equal(t.s2, p.stage2?.name ?? null)
    }
  }

  rounds++
}
console.log(`双级串联策略模糊对照 ${rounds} 轮全部通过 ✔`)
