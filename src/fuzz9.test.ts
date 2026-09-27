/**
 * 源地址转换路径分析模糊对照：在缩小且完全可枚举的报文空间
 * （原空间 10.1.2.0/24、转换后空间 192.168.7.0/24、端口 0..31、{TCP, UDP}）上
 * 随机生成前级规则、后级规则、等长源地址映射（源 / 转换后网段各自两两不重叠）
 * 与完全落在映射源网段内的目标，逐报文暴力执行「原地址前级首命中 → 仅放行
 * 报文按主机位一一转换 → 转换后地址后级首命中」，与 analyzeNatPath 的三类
 * 大小、分协议统计、轨迹分组大小、精确区域逐报文覆盖、代表报文轨迹与
 * 转换后地址逐一对账。
 * 规则 CIDR 全部在各自 /24 内对齐、端口均在 0..31 内，因此每个枚举报文代表
 * 1 条真实报文空间，引擎大小与枚举计数精确相等。
 */
import assert from 'node:assert'
import { analyzeNatPath } from './audit/natpath'
import type { NatPathCategory, NormalizedNatMapping } from './audit/natpath'
import { validateTandemTarget } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

const SRC_BASE = parseCidrStrict('10.1.2.0/24').start
const DST_BASE = parseCidrStrict('192.168.7.0/24').start
const MAX_PORT = 31
const PROTOS = ['TCP', 'UDP', 'ANY'] as const
const ACTIONS = ['allow', 'deny', 'drop'] as const

/** 指定 /24 内对齐的随机 CIDR，前缀 24..28；偶发非法（主机位非零） */
function randomCidr(base: number, badText: string) {
  if (rand(10) === 0) return badText // 非法：主机位非零
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const count = 256 / size
  const start = (base + rand(count) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}

function makeRules(tag: string, base: number, badText: string): RuleInput[] {
  const n = rand(7)
  return Array.from({ length: n }, (_, i) => {
    const a = rand(MAX_PORT + 1)
    const b = a + rand(MAX_PORT + 1 - a)
    return {
      id: `${tag}${i}`,
      name: `${tag}${i}`,
      cidr: randomCidr(base, badText),
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

/** 1..3 条等长映射：同一前缀，源块与转换后块各自不重复（保证两两不重叠） */
function makeMappings(): NormalizedNatMapping[] {
  const prefix = 25 + rand(4) // /25../28
  const size = 2 ** (32 - prefix)
  const blocks = 256 / size
  const k = 1 + rand(Math.min(3, blocks)) // 块数不超过可用块数
  const srcIdx = new Set<number>()
  while (srcIdx.size < k) srcIdx.add(rand(blocks))
  const dstIdx = new Set<number>()
  while (dstIdx.size < k) dstIdx.add(rand(blocks))
  const src = [...srcIdx]
  const dst = [...dstIdx]
  return src.map((s, i) => {
    const fromStart = (SRC_BASE + s * size) >>> 0
    const toStart = (DST_BASE + dst[i] * size) >>> 0
    return {
      fromStart,
      fromEnd: (fromStart + size - 1) >>> 0,
      toStart,
      toEnd: (toStart + size - 1) >>> 0,
      prefix,
      fromText: `${intToIpv4(fromStart)}/${prefix}`,
      toText: `${intToIpv4(toStart)}/${prefix}`,
      delta: toStart - fromStart,
    }
  })
}

/** 目标：随机取一条映射的源网段（或其更小的对齐子块），保证完全被映射源覆盖 */
function makeTarget(mappings: NormalizedNatMapping[]) {
  const m = mappings[rand(mappings.length)]
  const prefix = Math.min(32, m.prefix + rand(3))
  const size = 2 ** (32 - prefix)
  const count = (m.fromEnd - m.fromStart + 1) / size
  const start = (m.fromStart + rand(count) * size) >>> 0
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
  category: NatPathCategory
  s1: string | null // 前级首命中规则名；null = 未命中
  entered: boolean
  s2: string | null // 后级首命中规则名；null = 未命中 / 未进入
}

function bruteTrace(
  valid1: ReturnType<typeof validateRules>['valid'],
  valid2: ReturnType<typeof validateRules>['valid'],
  allow1: string[],
  allow2: string[],
  mappings: NormalizedNatMapping[],
  ip: number,
  port: number,
  proto: 'TCP' | 'UDP',
): Trace {
  const h1 = firstHit(valid1, ip, port, proto)
  if (!h1 || !allow1.includes(h1.action)) {
    return { category: 'blocked-stage1', s1: h1?.name ?? null, entered: false, s2: null }
  }
  const m = mappings.find((mm) => ip >= mm.fromStart && ip <= mm.fromEnd)
  if (!m) throw new Error(`目标地址 ${intToIpv4(ip)} 不在任何映射源网段内，用例生成有误`)
  const translated = (ip + m.delta) >>> 0
  const h2 = firstHit(valid2, translated, port, proto)
  if (!h2 || !allow2.includes(h2.action)) {
    return { category: 'blocked-stage2', s1: h1.name, entered: true, s2: h2?.name ?? null }
  }
  return { category: 'pass', s1: h1.name, entered: true, s2: h2.name }
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const rules1 = makeRules('A', SRC_BASE, '10.1.2.3/24')
  const rules2 = makeRules('B', DST_BASE, '192.168.7.3/24')
  const allow1 = makeAllowList()
  const allow2 = makeAllowList()
  const mappings = makeMappings()
  const targetInput = makeTarget(mappings)
  const { valid: valid1 } = validateRules(rules1)
  const { valid: valid2 } = validateRules(rules2)
  const { target, errors } = validateTandemTarget(targetInput)
  assert.equal(errors.length, 0)
  const result = analyzeNatPath(rules1, rules2, allow1, allow2, mappings, target!)

  // 暴力逐报文转换重放
  const catCount: Record<NatPathCategory, number> = {
    pass: 0,
    'blocked-stage1': 0,
    'blocked-stage2': 0,
  }
  const groupCount = new Map<string, number>()
  const catPackets = new Map<NatPathCategory, Array<{ ip: number; port: number; proto: 'TCP' | 'UDP' }>>()
  const perProto = {
    TCP: { pass: 0, b1: 0, b2: 0 },
    UDP: { pass: 0, b1: 0, b2: 0 },
  }
  for (const c of Object.keys(catCount) as NatPathCategory[]) catPackets.set(c, [])

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
  for (const cat of Object.keys(catCount) as NatPathCategory[]) {
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
  for (const cat of Object.keys(catCount) as NatPathCategory[]) {
    const expected = [...groupCount.keys()].filter((k) => k.startsWith(`${cat}|`))
    assert.equal(
      result.categories[cat].groups.length,
      expected.length,
      `round ${round} ${cat}: 分组数不符 engine=${result.categories[cat].groups.length} brute=${expected.length}; ${dump}`,
    )
  }
  for (const [key, count] of groupCount) {
    const [catRaw, s1, s2] = key.split('|')
    const cat = catRaw as NatPathCategory
    const g = result.categories[cat].groups.find(
      (x) =>
        (x.stage1?.name ?? null) === (s1 === '∅' ? null : s1) &&
        (x.stage2?.name ?? null) === (s2 === '∅' || s2 === '—' ? null : s2),
    )
    assert.ok(g, `round ${round}: 缺少轨迹分组 ${key}; ${dump}`)
    assert.equal(g!.size, count, `round ${round}: 分组 ${key} 大小不符; ${dump}`)
  }

  // 精确区域恰好覆盖暴力分类到的报文（原始地址空间，逐报文成员判定）
  for (const cat of Object.keys(catCount) as NatPathCategory[]) {
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

  // 每个轨迹分组与类别的代表报文暴力转换重放：轨迹、类别与转换后地址一致
  const checkPacket = (
    p: { srcIp: string; srcPort: number; protocol: 'TCP' | 'UDP'; translatedIp: string | null },
    expected: { category: NatPathCategory; s1: string | null; entered: boolean; s2: string | null },
  ) => {
    const ip = parseCidrStrict(`${p.srcIp}/32`).start
    const t = bruteTrace(valid1, valid2, allow1, allow2, mappings, ip, p.srcPort, p.protocol)
    assert.equal(t.category, expected.category, `round ${round}: 代表报文类别不符; ${dump}`)
    assert.equal(t.s1, expected.s1)
    assert.equal(t.entered, expected.entered)
    assert.equal(t.s2, expected.s2)
    if (t.entered) {
      const m = mappings.find((mm) => ip >= mm.fromStart && ip <= mm.fromEnd)!
      assert.equal(
        p.translatedIp,
        intToIpv4((ip + m.delta) >>> 0),
        `round ${round}: 转换后地址不符; ${dump}`,
      )
    } else {
      assert.equal(p.translatedIp, null, `round ${round}: 前级阻断不应有转换后地址; ${dump}`)
    }
  }
  for (const cat of Object.keys(catCount) as NatPathCategory[]) {
    for (const g of result.categories[cat].groups) {
      checkPacket(g.packet, {
        category: g.category,
        s1: g.stage1?.name ?? null,
        entered: g.enteredStage2,
        s2: g.stage2?.name ?? null,
      })
    }
    for (const p of result.categories[cat].examples) {
      checkPacket(p, {
        category: cat,
        s1: p.stage1?.name ?? null,
        entered: p.enteredStage2,
        s2: p.stage2?.name ?? null,
      })
    }
  }

  rounds++
}
console.log(`源地址转换路径分析模糊对照 ${rounds} 轮全部通过 ✔`)
