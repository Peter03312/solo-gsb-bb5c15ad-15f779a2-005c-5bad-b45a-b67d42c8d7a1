/**
 * 源地址转换路径分析（只读）。
 *
 * 在双级串联策略的两级放行流水线之间插入一级源地址转换（SNAT）：
 *   - 前级 = 当前规则列表，按**原始源地址**首命中求值；
 *   - 后级 = 用户粘贴的同格式 JSON 规则，作用在**转换后**的源地址上；
 *   - 两级各有一份「放行动作列表」（动作名精确匹配）；
 *   - 源地址映射 = 一组等长 IPv4 CIDR 对（源网段 → 转换后网段，前缀等长），
 *     地址按主机位一一对应平移（源端口与协议不改写）。
 *
 * 对目标空间（IPv4 CIDR × 端口区间 × 协议）中的每个报文：
 *   1. 先在前级规则上按「自上而下、首条命中」求值——未命中任何规则，
 *      或首命中动作不在前级放行列表内 → 前级阻断，不发生转换，
 *      也不再进入后级；
 *   2. 通过前级的报文，源地址按所在映射源网段平移到转换后网段
 *      （主机位不变），随后以后级规则重放——未命中或首命中动作不在
 *      后级放行列表内 → 后级阻断；
 *   3. 两级都放行 → 最终通过。
 *
 * 目标必须完全落在映射源网段（并集）内，否则目标中存在无法转换的地址，
 * 输入即判非法。后级规则的 CIDR 边界位于转换后空间：逐条与每个映射的
 * 转换后网段求交并逆映射（按主机位平移回源网段）得到原始空间中的等价
 * 区间；这些逆映射边界与映射源网段边界、目标边界、前级规则边界共同进入
 * 同一次原子切分（buildIpAtoms / buildPortAtoms 与规则顺序无关）。随后在
 * 该合并空间上构建前级 owner 表，并按后级规则顺序在其逆映射区间上登记
 * 首命中 owner，逐单元串联重放。整个目标空间被精确划分为互斥且完备的
 * 三类：
 *
 *   - 最终通过    pass
 *   - 前级阻断    blocked-stage1（未命中 或 动作不在放行列表；不发生转换）
 *   - 后级阻断    blocked-stage2（未命中 或 动作不在放行列表）
 *
 * 非法规则与停用规则在两级都按既有语义排除（不参与原子空间构建与首命中
 * 计算），并分别计数说明。每个类别与每条「分级命中轨迹」分组都给出报文
 * 空间大小、精确区域（协议 → 连续端口段 × 规范 CIDR 行，复用
 * buildExactRegions，均为**原始地址空间**）与确定性、可复制的代表报文
 * （取组内字典序最小单元，选点规则与引擎示例报文一致；进入后级的报文
 * 同时给出转换后地址）。分析全程只读，不修改任何规则。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  decodeCellKey,
  firstKey,
  packetFromKey,
  parseRulesJson,
  protocolDimIndices,
  validateRules,
} from './engine'
import { intToIpv4, ipv4ToInt, parseCidrStrict } from './iputil'
import { parseAllowActions, validateTandemTarget } from './tandem'
import type {
  NormalizedTandemTarget,
  TandemCategory,
  TandemProtocolBreakdown,
  TandemRuleRef,
  TandemStageStats,
  TandemTargetInput,
} from './tandem'
import type {
  ExactRegionGroup,
  NormalizedRule,
  Protocol,
  RuleInput,
} from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 输入：源地址映射、目标、放行动作列表、后级 JSON
// ---------------------------------------------------------------------------

/** 面板输入的一条源地址映射（原始文本形态） */
export interface SnatMappingInput {
  source: string
  translated: string
}

/** 校验通过后的规范映射：源网段与转换后网段前缀等长，地址按主机位平移 */
export interface NormalizedSnatMapping {
  srcStart: number
  srcEnd: number
  dstStart: number
  dstEnd: number
  prefix: number
  sourceText: string
  translatedText: string
}

/** 面板输入的完整表单（后级为原始 JSON 文本，映射为逐行文本） */
export interface SnatFormInput {
  stage2Json: string
  allow1Text: string
  allow2Text: string
  mappingsText: string
  target: TandemTargetInput
}

/**
 * 解析源地址映射文本：每行一条「源CIDR -> 转换后CIDR」
 * （分隔符支持 -> / → / => / 逗号 / 分号 / 空白）。要求：
 *   - 两个网段均为规范 IPv4 CIDR（与规则同一套严格校验）；
 *   - 二者前缀等长（主机位才能一一对应）；
 *   - 全部源网段两两不重叠（否则同一原始地址产生两种转换，无法确定唯一映射）。
 * 转换后网段之间允许重叠（每个原始地址的转换仍唯一，不影响路径分析）。
 */
export function parseSnatMappings(text: string): {
  mappings: NormalizedSnatMapping[]
  errors: string[]
} {
  const errors: string[] = []
  const mappings: NormalizedSnatMapping[] = []

  text.split('\n').forEach((line, i) => {
    const trimmed = line.trim()
    if (!trimmed) return
    const tokens = trimmed.split(/(?:->|→|=>|↦|,|，|;|；|\s+)/).filter(Boolean)
    if (tokens.length !== 2) {
      errors.push(
        `映射第 ${i + 1} 行：应形如 10.0.0.0/24 -> 192.168.0.0/24（每行一条，源网段与转换后网段等长）`,
      )
      return
    }
    let src: ReturnType<typeof parseCidrStrict>
    let dst: ReturnType<typeof parseCidrStrict>
    try {
      src = parseCidrStrict(tokens[0])
    } catch (err) {
      errors.push(`映射第 ${i + 1} 行源网段：${(err as Error).message}`)
      return
    }
    try {
      dst = parseCidrStrict(tokens[1])
    } catch (err) {
      errors.push(`映射第 ${i + 1} 行转换后网段：${(err as Error).message}`)
      return
    }
    if (src.prefix !== dst.prefix) {
      errors.push(
        `映射第 ${i + 1} 行：源网段 /${src.prefix} 与转换后网段 /${dst.prefix} 前缀长度不一致，` +
          '源地址转换要求等长映射（主机位一一对应）',
      )
      return
    }
    mappings.push({
      srcStart: src.start,
      srcEnd: src.end,
      dstStart: dst.start,
      dstEnd: dst.end,
      prefix: src.prefix,
      sourceText: src.canonical,
      translatedText: dst.canonical,
    })
  })

  if (mappings.length === 0 && errors.length === 0) {
    errors.push('源地址映射不能为空（每行一条：源CIDR -> 转换后CIDR，二者前缀等长）')
  }

  // 源网段两两不重叠：按起点排序后，与此前右端最大者比较即可发现全部重叠
  const sorted = [...mappings].sort((a, b) => a.srcStart - b.srcStart)
  let maxEnd = -1
  let maxHolder: NormalizedSnatMapping | null = null
  for (const m of sorted) {
    if (maxHolder && m.srcStart <= maxEnd) {
      errors.push(
        `映射源网段重叠：${maxHolder.sourceText} 与 ${m.sourceText}` +
          '（同一原始地址会产生两种转换，无法确定唯一映射）',
      )
    }
    if (m.srcEnd > maxEnd) {
      maxEnd = m.srcEnd
      maxHolder = m
    }
  }

  return { mappings, errors }
}

/**
 * 目标区间是否被映射源网段并集完全覆盖。
 * 源网段两两不重叠，排序后合并相邻段，检查目标是否落在某个连续段内
 * （目标跨多条相邻源网段也合法：每个地址仍唯一映射）。
 */
export function targetCoveredByMappings(
  target: { ipStart: number; ipEnd: number },
  mappings: NormalizedSnatMapping[],
): boolean {
  const sorted = [...mappings].sort((a, b) => a.srcStart - b.srcStart)
  let curStart = -1
  let curEnd = -1
  for (const m of sorted) {
    if (curStart === -1) {
      curStart = m.srcStart
      curEnd = m.srcEnd
      continue
    }
    if (m.srcStart > curEnd + 1) {
      if (curStart <= target.ipStart && target.ipEnd <= curEnd) return true
      curStart = m.srcStart
      curEnd = m.srcEnd
    } else {
      curEnd = Math.max(curEnd, m.srcEnd)
    }
  }
  return curStart !== -1 && curStart <= target.ipStart && target.ipEnd <= curEnd
}

// ---------------------------------------------------------------------------
// 结果类型
// ---------------------------------------------------------------------------

/** 可复制的代表报文（原始地址；进入后级时附转换后地址） */
export interface SnatPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
  /**
   * 进入后级时的转换后源地址（主机位一一映射，端口与协议不变）；
   * 前级阻断未进入后级时为 null（不发生转换）
   */
  translatedSrcIp: string | null
}

/** 类别代表报文及其分级命中轨迹 */
export interface SnatExample extends SnatPacket {
  /** 前级首命中规则；null = 前级未命中任何规则 */
  stage1: TandemRuleRef | null
  /** 是否通过前级、经转换后进入后级 */
  enteredStage2: boolean
  /** 后级首命中规则（按转换后地址判定）；null = 后级未命中 或 未进入后级 */
  stage2: TandemRuleRef | null
}

/** 一条分级命中轨迹分组：同一组内每个单元的两级首命中者完全相同 */
export interface SnatTraceGroup {
  category: TandemCategory
  /** 前级首命中规则；null = 前级未命中任何规则 */
  stage1: TandemRuleRef | null
  /** 是否进入后级（前级阻断的分组恒为 false） */
  enteredStage2: boolean
  /** 后级首命中规则；null = 后级未命中 或 未进入后级 */
  stage2: TandemRuleRef | null
  size: number
  cells: number
  /** 精确区域（原始地址空间） */
  regions: ExactRegionGroup[]
  /** 组内字典序最小单元的确定性代表报文（进入后级时含转换后地址） */
  packet: SnatPacket
}

/** 一个类别的汇总：总量 + 精确区域 + 带轨迹的代表报文 + 轨迹分组 */
export interface SnatCategorySummary {
  category: TandemCategory
  size: number
  cells: number
  ratio: number
  regions: ExactRegionGroup[]
  /** 每个具体协议至多一个代表报文（TCP / UDP 各一），附分级命中轨迹与转换后地址 */
  examples: SnatExample[]
  groups: SnatTraceGroup[]
}

export interface SnatResult {
  generatedAt: string
  target: NormalizedTandemTarget
  /** 两级实际使用的放行动作列表（已解析、去重） */
  allow1: string[]
  allow2: string[]
  /** 实际使用的源地址映射（已规范化，源网段两两不重叠） */
  mappings: NormalizedSnatMapping[]
  /** 目标报文空间总大小（ANY 目标为 TCP / UDP 两协议合计） */
  totalSize: number
  categories: Record<TandemCategory, SnatCategorySummary>
  /** 按 TCP / UDP 分别统计（ANY 目标时两协议各自独立重放） */
  perProtocol: TandemProtocolBreakdown[]
  stage1: TandemStageStats
  stage2: TandemStageStats
}

export type SnatOutcome =
  | { ok: true; result: SnatResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

interface Range {
  start: number
  end: number
}

function makeRuleRef(rule: NormalizedRule): TandemRuleRef {
  return { index: rule.index, name: rule.name, action: rule.action }
}

/**
 * 后级规则的声明 CIDR 位于转换后空间：与每个映射的转换后网段求交，
 * 按主机位平移回对应源网段，得到原始空间中的等价区间（逆映射）。
 * 映射源网段两两不重叠，故所得区间也两两不重叠。
 */
export function preimageRanges(
  rule: Pick<NormalizedRule, 'ipStart' | 'ipEnd'>,
  mappings: NormalizedSnatMapping[],
): Range[] {
  const out: Range[] = []
  for (const m of mappings) {
    const lo = Math.max(rule.ipStart, m.dstStart)
    const hi = Math.min(rule.ipEnd, m.dstEnd)
    if (lo > hi) continue
    out.push({
      start: (m.srcStart + (lo - m.dstStart)) >>> 0,
      end: (m.srcStart + (hi - m.dstStart)) >>> 0,
    })
  }
  return out
}

/**
 * 在给定目标、两级规则与源地址映射上执行转换路径重放。
 * 纯函数：不修改任何输入规则。调用前须保证映射合法（等长、源网段不重叠）
 * 且目标完全落在映射源网段内（evaluateSnat 已校验）。
 */
export function analyzeSnat(
  stage1Rules: RuleInput[],
  stage2Rules: RuleInput[],
  allow1: string[],
  allow2: string[],
  mappings: NormalizedSnatMapping[],
  target: NormalizedTandemTarget,
  now: Date = new Date(),
): SnatResult {
  // 非法规则与停用规则均按既有语义排除，不参与首命中计算
  const v1 = validateRules(stage1Rules)
  const v2 = validateRules(stage2Rules)
  const active1 = v1.valid.filter((r) => r.enabled)
  const active2 = v2.valid.filter((r) => r.enabled)
  const stage1Stats: TandemStageStats = {
    total: stage1Rules.length,
    active: active1.length,
    invalid: v1.invalid.length,
    disabled: v1.valid.length - active1.length,
  }
  const stage2Stats: TandemStageStats = {
    total: stage2Rules.length,
    active: active2.length,
    invalid: v2.invalid.length,
    disabled: v2.valid.length - active2.length,
  }

  // 合并原子空间：目标边界、前级规则边界、映射源网段边界与后级规则
  // 边界的逆映射共同参与切分。映射源网段边界保证每个目标原子完整落在
  // 某个源网段内（转换方式在原子内唯一）；逆映射边界保证每个原子相对
  // 每条后级规则要么整体命中、要么整体不命中。
  const preimages = active2.map((r) => preimageRanges(r, mappings))
  const ipAtoms = buildIpAtoms(active1, [
    { start: target.ipStart, end: target.ipEnd },
    ...mappings.map((m) => ({ start: m.srcStart, end: m.srcEnd })),
    ...preimages.flat(),
  ])
  const portAtoms = buildPortAtoms([...active1, ...active2], [
    { start: target.portStart, end: target.portEnd },
  ])
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)

  // 后级 owner：按规则顺序在其逆映射区间 × 端口 × 协议上登记首命中
  // （等价于把报文转换后地址放到后级规则上首命中，但全程在原始空间进行）
  const owner2 = new Map<string, number>()
  active2.forEach((rule, rulePos) => {
    const rulePortIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    const ruleProtoIdx = protocolDimIndices(rule.protocol)
    for (const range of preimages[rulePos]) {
      const rangeIpIdx = containedIndices(ipAtoms, range.start, range.end)
      for (const ip of rangeIpIdx) {
        for (const port of rulePortIdx) {
          for (const proto of ruleProtoIdx) {
            const key = `${ip}.${port}.${proto}`
            if (!owner2.has(key)) owner2.set(key, rulePos)
          }
        }
      }
    }
  })

  const allowSet1 = new Set(allow1)
  const allowSet2 = new Set(allow2)

  const ipIdx = containedIndices(ipAtoms, target.ipStart, target.ipEnd)
  const portIdx = containedIndices(portAtoms, target.portStart, target.portEnd)
  const protoIdx = protocolDimIndices(target.protocol)

  const categoryKeys: Record<TandemCategory, Set<string>> = {
    pass: new Set(),
    'blocked-stage1': new Set(),
    'blocked-stage2': new Set(),
  }
  // 轨迹分组键：b1|m（前级未命中）、b1|i（前级命中规则 i 但未放行）、
  // b2|i|m（后级未命中）、b2|i|j（后级命中规则 j 但未放行）、p|i|j（双放行）
  const groupKeys = new Map<string, Set<string>>()
  const addToGroup = (tag: string, key: string) => {
    let set = groupKeys.get(tag)
    if (!set) {
      set = new Set()
      groupKeys.set(tag, set)
    }
    set.add(key)
  }

  const perProto = [
    { pass: 0, b1: 0, b2: 0 },
    { pass: 0, b1: 0, b2: 0 },
  ]

  for (const ip of ipIdx) {
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`
        const pos1 = owner1.get(key)
        let category: TandemCategory
        if (pos1 === undefined) {
          category = 'blocked-stage1'
          addToGroup('b1|m', key)
        } else if (!allowSet1.has(active1[pos1].action)) {
          category = 'blocked-stage1'
          addToGroup(`b1|${pos1}`, key)
        } else {
          // 通过前级：源地址按主机位映射后进入后级重放
          // （owner2 已在逆映射空间构建，直接用原始单元 key 查询）
          const pos2 = owner2.get(key)
          if (pos2 === undefined) {
            category = 'blocked-stage2'
            addToGroup(`b2|${pos1}|m`, key)
          } else if (!allowSet2.has(active2[pos2].action)) {
            category = 'blocked-stage2'
            addToGroup(`b2|${pos1}|${pos2}`, key)
          } else {
            category = 'pass'
            addToGroup(`p|${pos1}|${pos2}`, key)
          }
        }
        categoryKeys[category].add(key)
        if (category === 'pass') perProto[proto].pass += size
        else if (category === 'blocked-stage1') perProto[proto].b1 += size
        else perProto[proto].b2 += size
      }
    }
  }

  const totalSize =
    perProto[0].pass +
    perProto[0].b1 +
    perProto[0].b2 +
    perProto[1].pass +
    perProto[1].b1 +
    perProto[1].b2
  const ratio = (n: number) => (totalSize === 0 ? 0 : n / totalSize)

  // 源地址转换：目标内地址必落在某个映射源网段内（目标已被校验完全覆盖）
  const translateIp = (ip: number): number => {
    for (const m of mappings) {
      if (ip >= m.srcStart && ip <= m.srcEnd) {
        return (m.dstStart + (ip - m.srcStart)) >>> 0
      }
    }
    throw new Error('目标内地址应总落在某个映射源网段内')
  }

  const packetOf = (key: string, enteredStage2: boolean): SnatPacket => {
    const base = packetFromKey(key, ipAtoms, portAtoms)
    return {
      ...base,
      translatedSrcIp: enteredStage2
        ? intToIpv4(translateIp(ipv4ToInt(base.srcIp)))
        : null,
    }
  }

  /** 重放一个单元的转换路径轨迹（用于类别代表报文的轨迹标注） */
  const traceOfKey = (key: string): SnatExample => {
    const pos1 = owner1.get(key)
    const entered = pos1 !== undefined && allowSet1.has(active1[pos1].action)
    const pos2 = entered ? owner2.get(key) : undefined
    return {
      ...packetOf(key, entered),
      stage1: pos1 === undefined ? null : makeRuleRef(active1[pos1]),
      enteredStage2: entered,
      stage2: pos2 === undefined ? null : makeRuleRef(active2[pos2]),
    }
  }

  const summarizeKeys = (keys: Set<string>) => {
    let size = 0
    for (const key of keys) {
      const { ip, port } = decodeCellKey(key)
      size += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    return size
  }

  const buildGroup = (tag: string, keys: Set<string>): SnatTraceGroup => {
    const parts = tag.split('|')
    const category: TandemCategory =
      parts[0] === 'p' ? 'pass' : parts[0] === 'b1' ? 'blocked-stage1' : 'blocked-stage2'
    const stage1 = parts[1] === 'm' ? null : makeRuleRef(active1[Number(parts[1])])
    const enteredStage2 = category !== 'blocked-stage1'
    const stage2 =
      !enteredStage2 || parts[2] === 'm'
        ? null
        : makeRuleRef(active2[Number(parts[2])])
    return {
      category,
      stage1,
      enteredStage2,
      stage2,
      size: summarizeKeys(keys),
      cells: keys.size,
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      packet: packetOf(firstKey(keys), enteredStage2),
    }
  }

  const groupsByCategory = new Map<TandemCategory, SnatTraceGroup[]>()
  for (const [tag, keys] of groupKeys) {
    const group = buildGroup(tag, keys)
    let list = groupsByCategory.get(group.category)
    if (!list) {
      list = []
      groupsByCategory.set(group.category, list)
    }
    list.push(group)
  }
  const refSortKey = (ref: TandemRuleRef | null) =>
    ref === null ? Number.MAX_SAFE_INTEGER : ref.index
  for (const list of groupsByCategory.values()) {
    list.sort(
      (a, b) =>
        b.size - a.size ||
        refSortKey(a.stage1) - refSortKey(b.stage1) ||
        refSortKey(a.stage2) - refSortKey(b.stage2),
    )
  }

  const buildCategory = (category: TandemCategory): SnatCategorySummary => {
    const keys = categoryKeys[category]
    // 代表报文：每个具体协议取该类别内字典序最小单元（确定性、可复现）
    const firstByProto = new Map<number, string>()
    for (const key of keys) {
      const { proto } = decodeCellKey(key)
      const cur = firstByProto.get(proto)
      if (cur === undefined || key < cur) firstByProto.set(proto, key)
    }
    const size = summarizeKeys(keys)
    return {
      category,
      size,
      cells: keys.size,
      ratio: ratio(size),
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      examples: [0, 1]
        .map((proto) => firstByProto.get(proto))
        .filter((k): k is string => k !== undefined)
        .map(traceOfKey),
      groups: groupsByCategory.get(category) ?? [],
    }
  }

  const categories: Record<TandemCategory, SnatCategorySummary> = {
    pass: buildCategory('pass'),
    'blocked-stage1': buildCategory('blocked-stage1'),
    'blocked-stage2': buildCategory('blocked-stage2'),
  }

  return {
    generatedAt: now.toISOString(),
    target,
    allow1: [...allow1],
    allow2: [...allow2],
    mappings: mappings.map((m) => ({ ...m })),
    totalSize,
    categories,
    perProtocol: [0, 1].map((proto) => ({
      protocol: (proto === 0 ? 'TCP' : 'UDP') as ConcreteProtocol,
      passSize: perProto[proto].pass,
      blockedStage1Size: perProto[proto].b1,
      blockedStage2Size: perProto[proto].b2,
    })),
    stage1: stage1Stats,
    stage2: stage2Stats,
  }
}

/**
 * 面板入口：校验目标、放行动作列表、源地址映射与后级 JSON 结构，
 * 任一错误都阻止分析；全部通过后执行转换路径重放。
 * 后级 JSON 与「粘贴 JSON 导入」同格式（数组 / { rules } / { entries }）；
 * 其中的非法规则、停用规则（enabled=false）按既有语义保留并排除。
 * 目标必须完全落在映射源网段（并集）内，否则目标中存在无法转换的地址。
 */
export function evaluateSnat(
  stage1Rules: RuleInput[],
  form: SnatFormInput,
  now: Date = new Date(),
): SnatOutcome {
  const errors: string[] = []

  const { target, errors: targetErrors } = validateTandemTarget(form.target)
  errors.push(...targetErrors)

  const allow1 = parseAllowActions(form.allow1Text)
  const allow2 = parseAllowActions(form.allow2Text)
  if (allow1.length === 0) {
    errors.push('前级放行动作列表不能为空（至少填写一个动作，多个动作用逗号或空格分隔）')
  }
  if (allow2.length === 0) {
    errors.push('后级放行动作列表不能为空（至少填写一个动作，多个动作用逗号或空格分隔）')
  }

  const { mappings, errors: mappingErrors } = parseSnatMappings(form.mappingsText)
  errors.push(...mappingErrors)

  if (target && mappingErrors.length === 0 && !targetCoveredByMappings(target, mappings)) {
    errors.push(
      `目标 ${target.cidrText} 未完全落在映射源网段内：` +
        '源地址转换要求目标中的每个地址都能按主机位一一映射',
    )
  }

  let stage2Rules: RuleInput[] = []
  if (!form.stage2Json.trim()) {
    errors.push('后级规则 JSON 不能为空（粘贴与「粘贴 JSON 导入」同格式的规则数组）')
  } else {
    const parsed = parseRulesJson(form.stage2Json)
    if (parsed.errors.length > 0) {
      errors.push(...parsed.errors.map((e) => `后级 JSON：${e}`))
    } else {
      stage2Rules = parsed.rules
    }
  }

  if (errors.length > 0 || !target) return { ok: false, errors }
  return {
    ok: true,
    result: analyzeSnat(stage1Rules, stage2Rules, allow1, allow2, mappings, target, now),
  }
}
