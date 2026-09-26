/**
 * 双级串联策略分析（只读）。
 *
 * 把两套规则串联成两级放行流水线：
 *   - 第一阶段 = 当前规则列表；
 *   - 第二阶段 = 用户粘贴的同格式 JSON 规则；
 *   - 每个阶段各有一份「放行动作列表」（动作名精确匹配）。
 *
 * 对目标空间（IPv4 CIDR × 端口区间 × 协议）中的每个报文：
 *   1. 先在第一阶段规则上按「自上而下、首条命中」求值——
 *      未命中任何规则，或首命中动作不在第一阶段放行列表内 → 第一阶段阻断，
 *      不再进入第二阶段；
 *   2. 通过第一阶段的报文**原样**（源 IP / 源端口 / 协议均不改写）进入
 *      第二阶段规则重放——未命中或首命中动作不在第二阶段放行列表内
 *      → 第二阶段阻断；
 *   3. 两阶段都放行 → 最终通过。
 *
 * 目标边界与**双方**规则的 CIDR / 端口边界合并进同一次原子切分
 * （buildIpAtoms / buildPortAtoms 与规则顺序无关），随后在该合并空间上
 * 分别构建两阶段的首命中 owner 表，逐单元串联重放。整个目标空间被精确
 * 划分为互斥且完备的三类：
 *
 *   - 最终通过      pass
 *   - 第一阶段阻断  blocked-stage1（未命中 或 动作不在放行列表）
 *   - 第二阶段阻断  blocked-stage2（未命中 或 动作不在放行列表）
 *
 * 非法规则与停用规则在两个阶段都按既有语义排除（不参与原子空间构建与
 * 首命中计算），并分别计数说明。每个类别与每条「分阶段命中轨迹」分组都
 * 给出报文空间大小、精确区域（协议 → 连续端口段 × 规范 CIDR 行，复用
 * buildExactRegions）与确定性、可复制的代表报文（取组内字典序最小单元，
 * 选点规则与引擎示例报文一致）。分析全程只读，不修改任何规则。
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
  validatePortRange,
  validateRules,
} from './engine'
import { parseCidrStrict } from './iputil'
import type {
  ExactRegionGroup,
  NormalizedRule,
  Protocol,
  RuleInput,
} from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 输入：目标、放行动作列表、第二阶段 JSON
// ---------------------------------------------------------------------------

/** 面板输入的分析目标（原始形态，端口允许字符串） */
export interface TandemTargetInput {
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
}

/** 校验通过后的规范目标 */
export interface NormalizedTandemTarget {
  ipStart: number
  ipEnd: number
  prefix: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
}

/** 面板输入的完整表单（第二阶段为原始 JSON 文本，放行列表为原始文本） */
export interface TandemFormInput {
  stage2Json: string
  allow1Text: string
  allow2Text: string
  target: TandemTargetInput
}

/** 目标校验：与规则 / 策略目标验证同一套严格标准；错误即阻止分析 */
export function validateTandemTarget(input: TandemTargetInput): {
  target: NormalizedTandemTarget | null
  errors: string[]
} {
  const errors: string[] = []

  let cidr: ReturnType<typeof parseCidrStrict> | null = null
  if (!input.cidr.trim()) {
    errors.push('目标 CIDR 不能为空')
  } else {
    try {
      cidr = parseCidrStrict(input.cidr)
    } catch (err) {
      errors.push((err as Error).message)
    }
  }

  const ports = validatePortRange(
    String(input.portStart).trim(),
    String(input.portEnd).trim(),
  )
  errors.push(...ports.errors)

  let protocol: Protocol | null = null
  const protoUpper = input.protocol.trim().toUpperCase()
  if (!protoUpper) {
    errors.push('协议不能为空')
  } else if (protoUpper !== 'TCP' && protoUpper !== 'UDP' && protoUpper !== 'ANY') {
    errors.push(`协议必须为 TCP / UDP / ANY，收到 “${input.protocol}”`)
  } else {
    protocol = protoUpper as Protocol
  }

  if (errors.length > 0 || !cidr || protocol === null) {
    return { target: null, errors }
  }
  return {
    target: {
      ipStart: cidr.start,
      ipEnd: cidr.end,
      prefix: cidr.prefix,
      cidrText: cidr.canonical,
      portStart: ports.portStart,
      portEnd: ports.portEnd,
      protocol,
    },
    errors: [],
  }
}

/**
 * 解析放行动作列表文本：按逗号 / 中文逗号、顿号、分号或空白分隔，
 * 去重并保持首次出现顺序；动作名为精确匹配（与规则动作逐字一致）。
 */
export function parseAllowActions(text: string): string[] {
  const out: string[] = []
  const seen = new Set<string>()
  for (const part of text.split(/[\s,，、;；]+/)) {
    const action = part.trim()
    if (!action || seen.has(action)) continue
    seen.add(action)
    out.push(action)
  }
  return out
}

// ---------------------------------------------------------------------------
// 结果类型
// ---------------------------------------------------------------------------

export type TandemCategory = 'pass' | 'blocked-stage1' | 'blocked-stage2'

export const TANDEM_CATEGORY_ORDER: TandemCategory[] = [
  'pass',
  'blocked-stage1',
  'blocked-stage2',
]

/** 对某一阶段首命中规则的引用（序号 / 名称 / 动作均取自该阶段自身的规则列表） */
export interface TandemRuleRef {
  index: number
  name: string
  action: string
}

/** 可复制的代表报文 */
export interface TandemPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
}

/** 类别代表报文及其分阶段命中轨迹 */
export interface TandemExample extends TandemPacket {
  /** 第一阶段首命中规则；null = 第一阶段未命中任何规则 */
  stage1: TandemRuleRef | null
  /** 是否通过第一阶段进入第二阶段 */
  enteredStage2: boolean
  /** 第二阶段首命中规则；null = 第二阶段未命中 或 未进入第二阶段 */
  stage2: TandemRuleRef | null
}

/** 一条分阶段命中轨迹分组：同一组内每个单元的两阶段首命中者完全相同 */
export interface TandemTraceGroup {
  category: TandemCategory
  /** 第一阶段首命中规则；null = 第一阶段未命中任何规则 */
  stage1: TandemRuleRef | null
  /** 是否进入第二阶段（第一阶段阻断的分组恒为 false） */
  enteredStage2: boolean
  /** 第二阶段首命中规则；null = 第二阶段未命中 或 未进入第二阶段 */
  stage2: TandemRuleRef | null
  size: number
  cells: number
  regions: ExactRegionGroup[]
  /** 组内字典序最小单元的确定性代表报文 */
  packet: TandemPacket
}

/** 一个类别的汇总：总量 + 精确区域 + 带轨迹的代表报文 + 轨迹分组 */
export interface TandemCategorySummary {
  category: TandemCategory
  size: number
  cells: number
  ratio: number
  regions: ExactRegionGroup[]
  /** 每个具体协议至多一个代表报文（TCP / UDP 各一），附分阶段命中轨迹 */
  examples: TandemExample[]
  groups: TandemTraceGroup[]
}

/** 一个阶段的规则构成（非法 / 停用规则不参与重放，仅计数说明） */
export interface TandemStageStats {
  total: number
  active: number
  invalid: number
  disabled: number
}

export interface TandemProtocolBreakdown {
  protocol: ConcreteProtocol
  passSize: number
  blockedStage1Size: number
  blockedStage2Size: number
}

export interface TandemResult {
  generatedAt: string
  target: NormalizedTandemTarget
  /** 两阶段实际使用的放行动作列表（已解析、去重） */
  allow1: string[]
  allow2: string[]
  /** 目标报文空间总大小（ANY 目标为 TCP / UDP 两协议合计） */
  totalSize: number
  categories: Record<TandemCategory, TandemCategorySummary>
  /** 按 TCP / UDP 分别统计（ANY 目标时两协议各自独立重放） */
  perProtocol: TandemProtocolBreakdown[]
  stage1: TandemStageStats
  stage2: TandemStageStats
}

export type TandemOutcome =
  | { ok: true; result: TandemResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

function makeRuleRef(rule: NormalizedRule): TandemRuleRef {
  return { index: rule.index, name: rule.name, action: rule.action }
}

/**
 * 在给定目标与两份规则上执行双级串联重放。纯函数：不修改任何输入规则。
 * allow1 / allow2 为已解析的放行动作列表（精确匹配规则动作）。
 */
export function analyzeTandem(
  stage1Rules: RuleInput[],
  stage2Rules: RuleInput[],
  allow1: string[],
  allow2: string[],
  target: NormalizedTandemTarget,
  now: Date = new Date(),
): TandemResult {
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

  // 合并原子空间：目标边界与双方规则的 CIDR / 端口边界共同参与切分，
  // 两阶段在同一套单元上逐一对齐重放首命中；报文本身不改写。
  const merged = [...active1, ...active2]
  const ipAtoms = buildIpAtoms(merged, [{ start: target.ipStart, end: target.ipEnd }])
  const portAtoms = buildPortAtoms(merged, [
    { start: target.portStart, end: target.portEnd },
  ])
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)
  const owner2 = buildOwnerMap(active2, ipAtoms, portAtoms)

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
  // 轨迹分组键：b1|m（一阶段未命中）、b1|i（一阶段命中规则 i 但未放行）、
  // b2|i|m（二阶段未命中）、b2|i|j（二阶段命中规则 j 但未放行）、p|i|j（双放行）
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
          // 通过第一阶段：报文原样进入第二阶段重放
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

  const packetOf = (key: string): TandemPacket => packetFromKey(key, ipAtoms, portAtoms)

  /** 重放一个单元的串联轨迹（用于类别代表报文的轨迹标注） */
  const traceOfKey = (key: string): TandemExample => {
    const pos1 = owner1.get(key)
    const entered =
      pos1 !== undefined && allowSet1.has(active1[pos1].action)
    const pos2 = entered ? owner2.get(key) : undefined
    return {
      ...packetOf(key),
      stage1: pos1 === undefined ? null : makeRuleRef(active1[pos1]),
      enteredStage2: entered,
      stage2:
        pos2 === undefined ? null : makeRuleRef(active2[pos2]),
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

  const buildGroup = (tag: string, keys: Set<string>): TandemTraceGroup => {
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
      packet: packetOf(firstKey(keys)),
    }
  }

  const groupsByCategory = new Map<TandemCategory, TandemTraceGroup[]>()
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

  const buildCategory = (category: TandemCategory): TandemCategorySummary => {
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

  const categories: Record<TandemCategory, TandemCategorySummary> = {
    pass: buildCategory('pass'),
    'blocked-stage1': buildCategory('blocked-stage1'),
    'blocked-stage2': buildCategory('blocked-stage2'),
  }

  return {
    generatedAt: now.toISOString(),
    target,
    allow1: [...allow1],
    allow2: [...allow2],
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
 * 面板入口：校验目标、放行动作列表与第二阶段 JSON 结构，
 * 任一错误都阻止分析；全部通过后执行双级串联重放。
 * 第二阶段 JSON 与「粘贴 JSON 导入」同格式（数组 / { rules } / { entries }）；
 * 其中的非法规则、停用规则（enabled=false）按既有语义保留并排除。
 */
export function evaluateTandem(
  stage1Rules: RuleInput[],
  form: TandemFormInput,
  now: Date = new Date(),
): TandemOutcome {
  const errors: string[] = []

  const { target, errors: targetErrors } = validateTandemTarget(form.target)
  errors.push(...targetErrors)

  const allow1 = parseAllowActions(form.allow1Text)
  const allow2 = parseAllowActions(form.allow2Text)
  if (allow1.length === 0) {
    errors.push('第一阶段放行动作列表不能为空（至少填写一个动作，多个动作用逗号或空格分隔）')
  }
  if (allow2.length === 0) {
    errors.push('第二阶段放行动作列表不能为空（至少填写一个动作，多个动作用逗号或空格分隔）')
  }

  let stage2Rules: RuleInput[] = []
  if (!form.stage2Json.trim()) {
    errors.push('第二阶段规则 JSON 不能为空（粘贴与「粘贴 JSON 导入」同格式的规则数组）')
  } else {
    const parsed = parseRulesJson(form.stage2Json)
    if (parsed.errors.length > 0) {
      errors.push(...parsed.errors.map((e) => `第二阶段 JSON：${e}`))
    } else {
      stage2Rules = parsed.rules
    }
  }

  if (errors.length > 0 || !target) return { ok: false, errors }
  return {
    ok: true,
    result: analyzeTandem(stage1Rules, stage2Rules, allow1, allow2, target, now),
  }
}
