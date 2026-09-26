/**
 * 流量样本归因。
 *
 * 粘贴一组流量样本（唯一 id × 源 IPv4 × 源端口 × 协议 × 正数权重），
 * 按「自上而下、首条命中」语义用当前合法且启用的规则逐条判定每个样本的
 * 命中规则与动作；非法 / 停用规则与审计一致地不参与判定。
 *
 * 协议为 ANY 的样本按同一权重分别判定 TCP 与 UDP：一条样本产生两条
 * 判定记录（各带原权重），二者可能命中不同规则而落入不同分组。
 *
 * 判定记录按「命中规则（及其动作）/ 未命中」分组汇总权重与占比
 * （占比 = 组权重 ÷ 全部判定记录权重之和），命中组按权重降序排列、
 * 未命中组固定列于最后；组内明细按权重降序（同权重按行号、协议）排列。
 *
 * 重复 id 或非法字段逐行报错，错误行不参与判定与统计。
 */
import { validateRules } from './engine'
import { parseIpv4Strict } from './iputil'
import type { NormalizedRule, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

const PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ANY']

/** 校验通过后的规范样本 */
export interface NormalizedSample {
  id: string
  /** 在粘贴数组中的行号（从 1 计） */
  line: number
  ip: number
  ipText: string
  port: number
  protocol: Protocol
  weight: number
}

/** 单行校验错误（该行不参与判定与统计）；line=0 表示整体输入错误（如 JSON 解析失败） */
export interface SampleLineError {
  line: number
  id: string | null
  errors: string[]
}

/** 一条判定记录：ANY 样本拆为 TCP / UDP 两条，各带原权重 */
export interface AttributionJudgement {
  id: string
  line: number
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
  weight: number
  matchedRuleIndex: number | null
  matchedRuleName: string | null
  action: string | null
}

/** 一个汇总分组：命中某条规则（含其动作），或未命中任何规则 */
export interface AttributionGroup {
  key: string
  matchedRuleIndex: number | null
  matchedRuleName: string | null
  action: string | null
  weight: number
  ratio: number
  /** 组内判定明细，按权重降序（同权重按行号升序、TCP 先于 UDP） */
  judgements: AttributionJudgement[]
}

export interface AttributionResult {
  generatedAt: string
  /** 参与判定的合法且启用的规则数 */
  activeRuleCount: number
  invalidExcluded: number
  disabledExcluded: number
  /** 合法样本行数（错误行不计入） */
  sampleCount: number
  /** 判定记录数（ANY 样本计两条） */
  judgementCount: number
  /** 全部判定记录权重之和（占比分母；ANY 样本的权重在两个协议各计一次） */
  totalWeight: number
  matchedWeight: number
  matchedRatio: number
  unmatchedWeight: number
  unmatchedRatio: number
  /** 命中分组，按权重降序（同权重按规则序号升序） */
  groups: AttributionGroup[]
  /** 未命中分组（无未命中判定时为 null），展示时固定列于最后 */
  unmatched: AttributionGroup | null
  /** 逐行错误（错误行不计入统计） */
  errors: SampleLineError[]
}

// ---------------------------------------------------------------------------
// 样本解析与逐行校验
// ---------------------------------------------------------------------------

/** 权重：正数；字符串仅接受十进制写法（拒绝 0x10、Infinity 等 Number 怪癖） */
const WEIGHT_RE = /^(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$/

function parseSampleWeight(v: unknown): { weight: number; error: string | null } {
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return { weight: NaN, error: 'weight 必须为有限数值' }
    if (v <= 0) return { weight: NaN, error: 'weight 必须为正数' }
    return { weight: v, error: null }
  }
  const text = typeof v === 'string' ? v.trim() : ''
  if (text === '') return { weight: NaN, error: 'weight 必须为正数（数值或数字字符串）' }
  if (!WEIGHT_RE.test(text)) return { weight: NaN, error: `weight 必须为正的十进制数值，收到 “${text}”` }
  const weight = Number(text)
  // 正则已限定十进制写法，但仍可能上溢 Infinity 或下溢 0（如 1e999 / 1e-999）
  if (!Number.isFinite(weight) || weight <= 0) {
    return { weight: NaN, error: 'weight 必须为有限的正数' }
  }
  return { weight, error: null }
}

function parseSamplePort(v: unknown): { port: number; error: string | null } {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) return { port: NaN, error: 'srcPort 必须为整数' }
    if (v < 0 || v > 65535) return { port: NaN, error: 'srcPort 必须在 0-65535 之间' }
    return { port: v, error: null }
  }
  const text = typeof v === 'string' ? v.trim() : ''
  if (text === '') return { port: NaN, error: 'srcPort 必须为 0-65535 的整数' }
  if (!/^\d+$/.test(text)) return { port: NaN, error: `srcPort 必须为整数，收到 “${text}”` }
  const port = Number(text)
  if (port > 65535) return { port: NaN, error: 'srcPort 必须在 0-65535 之间' }
  return { port, error: null }
}

/**
 * 解析粘贴的样本 JSON 数组并逐行校验。
 * 每行须为对象：{ id, srcIp, srcPort, protocol, weight }；
 * id 在整个数组内唯一（首次出现即登记，后续同名行报重复）；
 * 错误行全部收集（一行可多个错误），合法行照常进入后续判定。
 */
export function parseSamplesJson(text: string): {
  samples: NormalizedSample[]
  errors: SampleLineError[]
} {
  if (text.trim() === '') {
    return { samples: [], errors: [{ line: 0, id: null, errors: ['请先粘贴样本 JSON 数组'] }] }
  }
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    return {
      samples: [],
      errors: [{ line: 0, id: null, errors: [`JSON 解析失败：${(err as Error).message}`] }],
    }
  }
  if (!Array.isArray(data)) {
    return { samples: [], errors: [{ line: 0, id: null, errors: ['根节点必须是样本数组'] }] }
  }

  const samples: NormalizedSample[] = []
  const errors: SampleLineError[] = []
  /** id → 首次出现的行号（无论该行是否因其他字段错误被排除，均参与查重） */
  const firstLineOfId = new Map<string, number>()

  data.forEach((item, i) => {
    const line = i + 1
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      errors.push({ line, id: null, errors: ['不是对象，已跳过'] })
      return
    }
    const o = item as Record<string, unknown>
    const rowErrors: string[] = []

    // id：必填、非空、全数组唯一
    let id: string | null = null
    const rawId = o.id
    if (typeof rawId === 'string' && rawId.trim()) id = rawId.trim()
    else if (typeof rawId === 'number' && Number.isFinite(rawId)) id = String(rawId)
    if (id === null) {
      rowErrors.push('id 必须为非空字符串或数字')
    } else {
      const firstLine = firstLineOfId.get(id)
      if (firstLine !== undefined) {
        rowErrors.push(`id “${id}” 与第 ${firstLine} 条重复`)
      } else {
        firstLineOfId.set(id, line)
      }
    }

    // 源 IP：严格四段点分十进制
    let ip = 0
    let ipText = ''
    const rawIp = o.srcIp
    if (typeof rawIp !== 'string' || !rawIp.trim()) {
      rowErrors.push('srcIp 必须为点分十进制 IPv4 字符串')
    } else {
      try {
        const parsed = parseIpv4Strict(rawIp)
        ip = parsed.ip
        ipText = parsed.canonical
      } catch (err) {
        rowErrors.push(`srcIp：${(err as Error).message}`)
      }
    }

    // 源端口
    const port = parseSamplePort(o.srcPort)
    if (port.error !== null) rowErrors.push(port.error)

    // 协议（大小写不敏感，与规则一致）
    let protocol: Protocol | null = null
    const rawProto = typeof o.protocol === 'string' ? o.protocol : ''
    const protoUpper = rawProto.trim().toUpperCase()
    if (!protoUpper) {
      rowErrors.push('protocol 必须为 TCP / UDP / ANY')
    } else if (!PROTOCOLS.includes(protoUpper as Protocol)) {
      rowErrors.push(`protocol 必须为 TCP / UDP / ANY，收到 “${rawProto}”`)
    } else {
      protocol = protoUpper as Protocol
    }

    // 权重：正数
    const w = parseSampleWeight(o.weight)
    if (w.error !== null) rowErrors.push(w.error)

    if (rowErrors.length > 0) {
      errors.push({ line, id, errors: rowErrors })
      return
    }
    samples.push({ id: id!, line, ip, ipText, port: port.port, protocol: protocol!, weight: w.weight })
  })

  return { samples, errors }
}

// ---------------------------------------------------------------------------
// 首命中判定与分组汇总
// ---------------------------------------------------------------------------

/** 暴力首命中：按规则顺序返回第一条覆盖该报文的规则（与审计语义一致） */
function firstHit(
  active: NormalizedRule[],
  ip: number,
  port: number,
  proto: ConcreteProtocol,
): NormalizedRule | null {
  for (const r of active) {
    if (
      ip >= r.ipStart &&
      ip <= r.ipEnd &&
      port >= r.portStart &&
      port <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === proto)
    ) {
      return r
    }
  }
  return null
}

/**
 * 对粘贴的样本数组执行首命中归因。纯函数，不修改规则；
 * 同一（规则集, 样本文本）输入的结果完全一致。
 */
export function attributeSamples(
  rules: RuleInput[],
  text: string,
  now: Date = new Date(),
): AttributionResult {
  const { samples, errors } = parseSamplesJson(text)
  const { valid, invalid } = validateRules(rules)
  const active = valid.filter((r) => r.enabled)
  const disabledCount = valid.length - active.length

  // ANY 样本按同一权重分别判定 TCP 与 UDP（一条样本 → 两条判定记录）
  const judgements: AttributionJudgement[] = []
  for (const s of samples) {
    const protos: ConcreteProtocol[] = s.protocol === 'ANY' ? ['TCP', 'UDP'] : [s.protocol]
    for (const proto of protos) {
      const hit = firstHit(active, s.ip, s.port, proto)
      judgements.push({
        id: s.id,
        line: s.line,
        srcIp: s.ipText,
        srcPort: s.port,
        protocol: proto,
        weight: s.weight,
        matchedRuleIndex: hit ? hit.index : null,
        matchedRuleName: hit ? hit.name : null,
        action: hit ? hit.action : null,
      })
    }
  }

  const groupMap = new Map<string, AttributionGroup>()
  for (const j of judgements) {
    const key = j.matchedRuleIndex === null ? '#unmatched' : `rule:${j.matchedRuleIndex}`
    let group = groupMap.get(key)
    if (!group) {
      group = {
        key,
        matchedRuleIndex: j.matchedRuleIndex,
        matchedRuleName: j.matchedRuleName,
        action: j.action,
        weight: 0,
        ratio: 0,
        judgements: [],
      }
      groupMap.set(key, group)
    }
    group.weight += j.weight
    group.judgements.push(j)
  }

  const totalWeight = judgements.reduce((sum, j) => sum + j.weight, 0)
  const unmatched = groupMap.get('#unmatched') ?? null
  const groups = [...groupMap.values()]
    .filter((g) => g.key !== '#unmatched')
    .sort((a, b) => b.weight - a.weight || a.matchedRuleIndex! - b.matchedRuleIndex!)

  for (const g of unmatched ? [...groups, unmatched] : groups) {
    g.ratio = totalWeight === 0 ? 0 : g.weight / totalWeight
    g.judgements.sort(
      (a, b) =>
        b.weight - a.weight ||
        a.line - b.line ||
        (a.protocol === b.protocol ? 0 : a.protocol === 'TCP' ? -1 : 1),
    )
  }

  const unmatchedWeight = unmatched ? unmatched.weight : 0
  const matchedWeight = totalWeight - unmatchedWeight
  const ratioOf = (n: number) => (totalWeight === 0 ? 0 : n / totalWeight)

  return {
    generatedAt: now.toISOString(),
    activeRuleCount: active.length,
    invalidExcluded: invalid.length,
    disabledExcluded: disabledCount,
    sampleCount: samples.length,
    judgementCount: judgements.length,
    totalWeight,
    matchedWeight,
    matchedRatio: ratioOf(matchedWeight),
    unmatchedWeight,
    unmatchedRatio: ratioOf(unmatchedWeight),
    groups,
    unmatched,
    errors,
  }
}
