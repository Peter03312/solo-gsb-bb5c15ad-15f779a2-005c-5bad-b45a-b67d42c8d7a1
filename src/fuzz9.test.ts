/**
 * 源地址转换路径分析模糊对照：在缩小且完全可枚举的报文空间（10.1.2.0/24
 * × 端口 0..31 × {TCP, UDP}）上随机生成两级规则集、放行动作列表、等长
 * 源地址映射（源网段互不重叠）与目标（始终落在某条映射源网段内），
 * 逐报文暴力执行「前级原始地址首命中 → 放行则按主机位映射转换源地址 →
 * 后级转换后地址首命中」，与 analyzeSnat 的三类大小、轨迹分组大小、
 * 精确区域逐报文覆盖、代表报文轨迹与转换后地址、分协议统计逐一对账。
 * 规则 CIDR 全部在 /24 内对齐、端口均在 0..31 内，因此每个枚举报文代表
 * 1 条真实报文空间，引擎大小与枚举计数精确相等。
 */
import assert from 'node:assert'
import { analyzeSnat } from './audit/snat'
import type { NormalizedSnatMapping } from './audit/snat'
import { validateTandemTarget } from './audit/tandem'
import type { TandemCategory } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

const BASE = parseCidrStrict('10.1.2.0/24').start
const DST_BASE = parseCidrStrict('172.16.5.0/24').start
const MAX_PORT = 31
const PROTOS = ['TCP', 'UDP', 'ANY'] as const
const ACTIONS = ['allow', 'deny', 'drop'] as const

/** 随机等长映射：源网段在 10.1.2.0/24 内对齐且互不重叠；转换后网段在 172.16.5.0/24 内对齐 */
function makeMappings(): NormalizedSnatMapping[] {
  const n = 1 + rand(3)
  const chosen: Array<{ start: number; end: number; prefix: number }> = []
  let guard = 0
  while (chosen.length < n && guard++ < 200) {
    const prefix = 25 + rand(4) // /25../28
    const size = 2 ** (32 - prefix)
    const start = (BASE + rand(256 / size) * size) >>> 0
    const end = (start + size - 1) >>> 0
    if (chosen.some((c) => !(end < c.start || start > c.end))) continue
    chosen.push({ start, end, prefix })
  }
  return chosen.map((c) => {
    const size = 2 ** (32 - c.prefix)
    const dStart = (DST_BASE + rand(256 / size) * size) >>> 0
    const dEnd = (dStart + size - 1) >>> 0
    return {
      srcStart: c.start,
      srcEnd: c.end,
      dstStart: dStart,
      dstEnd: dEnd,
      prefix: c.prefix,
      sourceText: `${intToIpv4(c.start)}/${c.prefix}`,
      translatedText: `${intToIpv4(dStart)}/${c.prefix}`,
    }
  })
}

/** /24 内对齐的随机 CIDR，前缀 24..28；偶发非法（主机位非零） */
function randomCidr(base: number, bad: string) {
  if (rand(10) === 0) return bad
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const start = (base + rand(256 / size) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}

function makeRules(tag: string, base: number, bad: string, any0: boolean): RuleInput[] {
  const n = rand(7)
  return Array.from({ length: n }, (_, i) => {
    const a = rand(MAX_PORT + 1)
    const b = a + rand(MAX_PORT + 1 - a)
    return {
      id: `${tag}${i}`,
      name: `${tag}${i}`,
      cidr: any0 && rand(6) === 0 ? '0.0.0.0/0' : randomCidr(base, bad),
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

/** 目标：随机一条映射源网段内的对齐子网段（保证完全落在映射内） */
function makeTarget(mappings: NormalizedSnatMapping[]) {
  const m = mappings[rand(mappings.length)]
  const maxPrefix = Math.min(28, m.prefix + 3)
  const prefix = m.prefix + rand(maxPrefix - m.prefix + 1)
  const size = 2 ** (32 - prefix)
  const count = (m.srcEnd - m.srcStart + 1) / size
  const start = (m.srcStart + rand(count) * size) >>> 0
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
  s1: string | null // 前级首命中规则名；null = 未命中
  entered: boolean
  s2: string | null // 后级首命中规则名；null = 未命中 / 未进入
}

function bruteTrace(
  valid1: ReturnType<typeof validateRules>['valid'],
  valid2: ReturnType<typeof validateRules>['valid'],
  allow1: string[],
  allow2: string[],
  mappings: NormalizedSnatMapping[],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
): Trace {
  const h1 = firstHit(valid1, ip, port, proto)
  if (!h1 || !allow1.includes(h1.action)) {
    return { category: 'blocked-stage1', s1: h1?.name ?? null, entered: false, s2: null }
  }
  const m = mappings.find((x) => ip >= x.srcStart && ip <= x.srcEnd)
  if (!m) throw new Error(`目标地址 ${intToIpv4(ip)} 应落在映射源网段内`)
  const tip = (m.dstStart + (ip - m.srcStart)) >>> 0
  const h2 = firstHit(valid2, tip, port, proto)
  if (!h2 || !allow2.includes(h2.action)) {
    return { category: 'blocked-stage2', s1: h1.name, entered: true, s2: h2?.name ?? null }
  }
  return { category: 'pass', s1: h1.name, entered: true, s2: h2.name }
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const mappings = makeMappings()
  const rules1 = makeRules('A', BASE, '10.1.2.3/24', false)
  const rules2 = makeRules('B', DST_BASE, '172.16.5.3/24', true)
  const allow1 = makeAllowList()
  const allow2 = makeAllowList()
  const targetInput = makeTarget(mappings)
  const { valid: valid1 } = validateRules(rules1)
  const { valid: valid2 } = validateRules(rules2)
  const { target, errors } = validateTandemTarget(targetInput)
  assert.equal(errors.length, 0)
  const result = analyzeSnat(rules1, rules2, allow1, allow2, mappings, target!)

  // 暴力逐报文转换路径重放
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

  const protos: Array<'TCP' | 'UDP'> =
    target!.protocol === 'ANY' ? ['TCP', 'UDP'] : [target!.protocol as 'TCP' | 'UDP']
  for (let ip = target!.ipStart; ip <= target!.ipEnd; ip++) {
    for (let port = target!.portStart; port <= target!.portEnd; port++) {
      for (const proto of protos) {
        const t = bruteTrace(valid1, valid2, allow1, allow2, mappings, ip, port, proto)
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

  const dump = `A=${JSON.stringify(rules1)} B=${JSON.stringify(rules2)} allow1=${allow1} allow2=${allow2} mappings=${JSON.stringify(mappings)} target=${JSON.stringify(targetInput)}`

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

  // 轨迹分组对账：暴力分组与引擎分组一一对应（按 类别|前级名|后级名）
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

  // 每个轨迹分组与类别的代表报文暴力重放：轨迹与转换后地址一致
  const translate = (ip: number): number => {
    const m = mappings.find((x) => ip >= x.srcStart && ip <= x.srcEnd)!
    return (m.dstStart + (ip - m.srcStart)) >>> 0
  }
  for (const cat of Object.keys(catCount) as TandemCategory[]) {
    for (const g of result.categories[cat].groups) {
      const p = g.packet
      const ip = parseCidrStrict(`${p.srcIp}/32`).start
      const t = bruteTrace(valid1, valid2, allow1, allow2, mappings, ip, p.srcPort, p.protocol)
      assert.equal(t.category, g.category, `round ${round}: 代表报文类别不符; ${dump}`)
      assert.equal(t.s1, g.stage1?.name ?? null)
      assert.equal(t.entered, g.enteredStage2)
      assert.equal(t.s2, g.stage2?.name ?? null)
      assert.equal(
        p.translatedSrcIp,
        t.entered ? intToIpv4(translate(ip)) : null,
        `round ${round}: 代表报文转换后地址不符; ${dump}`,
      )
    }
    for (const p of result.categories[cat].examples) {
      const ip = parseCidrStrict(`${p.srcIp}/32`).start
      const t = bruteTrace(valid1, valid2, allow1, allow2, mappings, ip, p.srcPort, p.protocol)
      assert.equal(t.category, cat)
      assert.equal(t.s1, p.stage1?.name ?? null)
      assert.equal(t.entered, p.enteredStage2)
      assert.equal(t.s2, p.stage2?.name ?? null)
      assert.equal(
        p.translatedSrcIp,
        t.entered ? intToIpv4(translate(ip)) : null,
        `round ${round}: 类别代表报文转换后地址不符; ${dump}`,
      )
    }
  }

  rounds++
}
console.log(`源地址转换路径分析模糊对照 ${rounds} 轮全部通过 ✔`)
