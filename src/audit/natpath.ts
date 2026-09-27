/**
 * 源地址转换路径分析（只读）。
 *
 * 在双级串联的基础上引入一层源地址转换（NAT）：
 *   - 前级 = 当前规则列表，按**原始源地址**做「自上而下、首条命中」判定；
 *   - 后级 = 用户粘贴的同格式 JSON 规则，按**转换后源地址**做首命中判定；
 *   - 两级各有一份「放行动作列表」（动作名精确匹配）；
 *   - 源地址映射 = 一组**等长**（源 / 转换后前缀长度一致）的 IPv4 CIDR 对，
 *     源网段内的地址按主机位一一映射到转换后网段（偏移量不变）。
 *
 * 对目标空间（IPv4 CIDR × 端口区间 × 协议）中的每个报文：
 *   1. 先在前级规则上按原地址求首命中——未命中任何规则，或首命中动作不在
 *      前级放行列表内 → 前级阻断（不转换、不进入后级）；
 *   2. 仅前级放行的报文按所属映射做主机位一一转换（源端口 / 协议不变），
 *      以转换后地址进入后级重放——未命中或动作不在后级放行列表内
 *      → 后级阻断；
 *   3. 两级都放行 → 最终通过。
 *
 * 切分：目标必须完全落在映射源网段内（输入校验保证，否则每个报文的转换
 * 结果未必有定义）。把目标边界、前级规则边界、映射源网段边界，以及
 * **后级规则 CIDR 边界经逆映射回原空间的边界**（后级规则区间 ∩ 各映射
 * 转换后网段，平移回对应源网段）合并进同一次原子切分。由于映射等长，
 * 逆映射边界是精确平移；任一原空间原子块经转换后的像内部不再被任何
 * 后级边界切开，因此每个原子单元的两级归宿一致，可以逐单元精确分类。
 *
 * 输出：目标空间被精确划分为互斥且完备的三类——
 *
 *   - 最终通过      pass
 *   - 前级阻断      blocked-stage1（未命中 或 动作不在放行列表，不转换）
 *   - 后级阻断      blocked-stage2（转换后未命中 或 动作不在放行列表）
 *
 * 各自给出**原始地址空间**的报文空间大小、精确区域（协议 → 连续端口段 ×
 * 规范 CIDR 行，复用 buildExactRegions）与确定性、可复制的代表报文；
 * 代表报文同时标注转换后地址（前级阻断的报文不转换，无转换后地址）与
 * 两级命中轨迹。非法规则与停用规则在两级都按既有语义排除（不参与原子
 * 空间构建与首命中计算）并分别计数；分析全程只读，不修改任何规则。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  decodeCellKey,
  exampleIp,
  firstKey,
  packetFromKey,
  parseRulesJson,
  protocolDimIndices,
  validateRules,
} from './engine'
import { intToIpv4, parseCidrStrict } from './iputil'
import { parseAllowActions, validateTandemTarget } from './tandem'
import type {
  NormalizedTandemTarget,
  TandemRuleRef,
  TandemStageStats,
  TandemTargetInput,
} from './tandem'
import type {
  ExactRegionGroup,
  IpAtom,
  NormalizedRule,
  Protocol,
  RuleInput,
} from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 输入：源地址映射（等长 CIDR 对）、目标、放行动作列表、后级 JSON
// ---------------------------------------------------------------------------

/** 校验通过后的源地址映射：源网段内地址 + delta 即转换后地址（主机位一一对应） */
export interface NormalizedNatMapping {
  fromStart: number
  fromEnd: number
  toStart: number
  toEnd: number
  prefix: number
  fromText: string
  toText: string
  /** 转换后地址 = 原地址 + delta（可负；仅当原地址落在源网段内时有意义） */
  delta: number
}

/** 面板输入的完整表单（后级为原始 JSON 文本，映射为逐行文本，放行列表为原始文本） */
export interface NatPathFormInput {
  stage2Json: string
  allow1Text: string
  allow2Text: string
  mappingText: string
  target: TandemTargetInput
}

/**
 * 解析源地址映射文本：每行一条 `源CIDR -> 转换后CIDR`（也接受 →）。
 * 要求：两条 CIDR 均合法且**前缀长度相等**（等长才能按主机位一一映射）；
 * 全部源网段两两不重叠（同一原地址只能有一种转换）；
 * 全部转换后网段两两不重叠（否则逆映射不唯一，无法精确还原原空间边界）。
 */
export function parseNatMappings(text: string): {
  mappings: NormalizedNatMapping[]
  errors: string[]
} {
  const errors: string[] = []
  const mappings: NormalizedNatMapping[] = []
  const lineNos: number[] = [] // mappings[i] 所在的原始行号（用于错误定位）

  text.split('\n').forEach((raw, idx) => {
    const line = raw.trim()
    if (!line) return
    const parts = line.split(/->|→/).map((s) => s.trim())
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      errors.push(`第 ${idx + 1} 行：映射须形如 10.0.0.0/24 -> 172.16.0.0/24`)
      return
    }
    let from: ReturnType<typeof parseCidrStrict> | null = null
    let to: ReturnType<typeof parseCidrStrict> | null = null
    try {
      from = parseCidrStrict(parts[0])
    } catch (err) {
      errors.push(`第 ${idx + 1} 行源网段：${(err as Error).message}`)
    }
    try {
      to = parseCidrStrict(parts[1])
    } catch (err) {
      errors.push(`第 ${idx + 1} 行转换后网段：${(err as Error).message}`)
    }
    if (!from || !to) return
    if (from.prefix !== to.prefix) {
      errors.push(
        `第 ${idx + 1} 行：源网段与转换后网段前缀长度必须相等（/${from.prefix} 与 /${to.prefix}），否则无法按主机位一一映射`,
      )
      return
    }
    mappings.push({
      fromStart: from.start,
      fromEnd: from.end,
      toStart: to.start,
      toEnd: to.end,
      prefix: from.prefix,
      fromText: from.canonical,
      toText: to.canonical,
      delta: to.start - from.start,
    })
    lineNos.push(idx + 1)
  })

  if (mappings.length === 0 && errors.length === 0) {
    errors.push('源地址映射不能为空（每行一条：源CIDR -> 转换后CIDR）')
  }

  // 两两重叠检查：按起点排序后，有重叠必存在相邻重叠对
  const byFrom = mappings
    .map((m, i) => ({ m, line: lineNos[i] }))
    .sort((a, b) => a.m.fromStart - b.m.fromStart)
  for (let i = 1; i < byFrom.length; i++) {
    if (byFrom[i].m.fromStart <= byFrom[i - 1].m.fromEnd) {
      errors.push(
        `第 ${byFrom[i].line} 行与第 ${byFrom[i - 1].line} 行的映射源网段重叠` +
          `（${byFrom[i - 1].m.fromText} 与 ${byFrom[i].m.fromText}），同一地址只能有一种转换`,
      )
    }
  }
  const byTo = mappings
    .map((m, i) => ({ m, line: lineNos[i] }))
    .sort((a, b) => a.m.toStart - b.m.toStart)
  for (let i = 1; i < byTo.length; i++) {
    if (byTo[i].m.toStart <= byTo[i - 1].m.toEnd) {
      errors.push(
        `第 ${byTo[i].line} 行与第 ${byTo[i - 1].line} 行的转换后网段重叠` +
          `（${byTo[i - 1].m.toText} 与 ${byTo[i].m.toText}），逆映射不唯一`,
      )
    }
  }

  return { mappings, errors }
}

/**
 * 目标区间未被映射源网段并集完全覆盖时，返回首个未覆盖地址；完全覆盖返回 null。
 * 调用前映射须已通过 parseNatMappings 的重叠检查（源网段两两不重叠）。
 */
export function firstUncoveredIp(
  mappings: NormalizedNatMapping[],
  start: number,
  end: number,
): number | null {
  const sorted = [...mappings].sort((a, b) => a.fromStart - b.fromStart)
  let next = start
  for (const m of sorted) {
    if (m.fromEnd < next) continue
    if (m.fromStart > next) return next
    next = Math.max(next, m.fromEnd + 1)
    if (next > end) return null
  }
  return next > end ? null : next
}

// ---------------------------------------------------------------------------
// 结果类型
// ---------------------------------------------------------------------------

export type NatPathCategory = 'pass' | 'blocked-stage1' | 'blocked-stage2'

export const NATPATH_CATEGORY_ORDER: NatPathCategory[] = [
  'pass',
  'blocked-stage1',
  'blocked-stage2',
]

/** 可复制的代表报文：原始报文 + 转换后源地址（前级阻断未转换时为 null） */
export interface NatPathPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
  /** 进入后级时的转换后源地址；前级阻断未转换（未进入后级）时为 null */
  translatedIp: string | null
}

/** 类别代表报文及其两级命中轨迹 */
export interface NatPathExample extends NatPathPacket {
  /** 前级首命中规则；null = 前级未命中任何规则 */
  stage1: TandemRuleRef | null
  /** 是否通过前级（经转换）进入后级 */
  enteredStage2: boolean
  /** 后级首命中规则；null = 后级未命中 或 未进入后级 */
  stage2: TandemRuleRef | null
}

/** 一条两级命中轨迹分组：同一组内每个单元的两级首命中者完全相同 */
export interface NatPathTraceGroup {
  category: NatPathCategory
  stage1: TandemRuleRef | null
  enteredStage2: boolean
  stage2: TandemRuleRef | null
  size: number
  cells: number
  regions: ExactRegionGroup[]
  /** 组内字典序最小单元的确定性代表报文（含转换后地址） */
  packet: NatPathPacket
}

/** 一个类别的汇总：总量 + 原始空间精确区域 + 带轨迹的代表报文 + 轨迹分组 */
export interface NatPathCategorySummary {
  category: NatPathCategory
  size: number
  cells: number
  ratio: number
  regions: ExactRegionGroup[]
  /** 每个具体协议至多一个代表报文（TCP / UDP 各一），附转换后地址与两级命中轨迹 */
  examples: NatPathExample[]
  groups: NatPathTraceGroup[]
}

export interface NatPathProtocolBreakdown {
  protocol: ConcreteProtocol
  passSize: number
  blockedStage1Size: number
  blockedStage2Size: number
}

export interface NatPathResult {
  generatedAt: string
  target: NormalizedTandemTarget
  /** 两级实际使用的放行动作列表（已解析、去重） */
  allow1: string[]
  allow2: string[]
  /** 实际使用的源地址映射（已解析、等长、两两不重叠） */
  mappings: NormalizedNatMapping[]
  /** 目标报文空间总大小（ANY 目标为 TCP / UDP 两协议合计） */
  totalSize: number
  categories: Record<NatPathCategory, NatPathCategorySummary>
  /** 按 TCP / UDP 分别统计（ANY 目标时两协议各自独立重放） */
  perProtocol: NatPathProtocolBreakdown[]
  stage1: TandemStageStats
  stage2: TandemStageStats
}

export type NatPathOutcome =
  | { ok: true; result: NatPathResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 主分析流程
// ---------------------------------------------------------------------------

function makeRuleRef(rule: NormalizedRule): TandemRuleRef {
  return { index: rule.index, name: rule.name, action: rule.action }
}

/** 在已排序、互斥的原子数组中二分查找包含 ip 的原子下标 */
function findAtomIndexAt(atoms: IpAtom[], ip: number): number | undefined {
  let lo = 0
  let hi = atoms.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    const atom = atoms[mid]
    if (ip < atom.start) hi = mid - 1
    else if (ip > atom.end) lo = mid + 1
    else return mid
  }
  return undefined
}

/**
 * 在给定目标、两份规则与源地址映射上执行带转换的两级重放。
 * 纯函数：不修改任何输入规则。allow1 / allow2 为已解析的放行动作列表
 * （精确匹配规则动作）；mappings 须已通过 parseNatMappings 校验，
 * 且目标完全落在映射源网段内。
 */
export function analyzeNatPath(
  stage1Rules: RuleInput[],
  stage2Rules: RuleInput[],
  allow1: string[],
  allow2: string[],
  mappings: NormalizedNatMapping[],
  target: NormalizedTandemTarget,
  now: Date = new Date(),
): NatPathResult {
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

  // 后级 CIDR 边界逆映射回原空间：后级规则区间 ∩ 各映射转换后网段，
  // 平移回对应源网段。映射等长，逆映射边界是精确平移；这些边界参与
  // 原空间切分后，任一原空间原子块的转换后像内部不再含任何后级边界。
  const inverseExtras: Array<{ start: number; end: number }> = []
  for (const rule of active2) {
    for (const m of mappings) {
      const lo = Math.max(rule.ipStart, m.toStart)
      const hi = Math.min(rule.ipEnd, m.toEnd)
      if (lo <= hi) {
        inverseExtras.push({
          start: (lo - m.toStart + m.fromStart) >>> 0,
          end: (hi - m.toStart + m.fromStart) >>> 0,
        })
      }
    }
  }

  // 原空间切分：目标边界 + 前级规则边界 + 映射源网段边界 + 逆映射后级边界
  const ipAtoms = buildIpAtoms(active1, [
    { start: target.ipStart, end: target.ipEnd },
    ...mappings.map((m) => ({ start: m.fromStart, end: m.fromEnd })),
    ...inverseExtras,
  ])
  // 转换后空间切分：后级规则边界 + 映射转换后网段边界（仅用于构建后级 owner 表）
  const ipAtoms2 = buildIpAtoms(
    active2,
    mappings.map((m) => ({ start: m.toStart, end: m.toEnd })),
  )
  // 端口维不转换：两级规则与目标端口边界合并进同一次切分
  const portAtoms = buildPortAtoms([...active1, ...active2], [
    { start: target.portStart, end: target.portEnd },
  ])
  const owner1 = buildOwnerMap(active1, ipAtoms, portAtoms)
  const owner2 = buildOwnerMap(active2, ipAtoms2, portAtoms)

  const allowSet1 = new Set(allow1)
  const allowSet2 = new Set(allow2)

  // 原空间原子 → 所属映射（源网段两两不重叠，每个原子至多属于一个映射）
  const atomMapping: Array<number | undefined> = new Array(ipAtoms.length).fill(undefined)
  mappings.forEach((m, mi) => {
    for (const i of containedIndices(ipAtoms, m.fromStart, m.fromEnd)) {
      atomMapping[i] = mi
    }
  })
  // 原空间原子 → 转换后像所在的后级原子下标（像内部无后级边界，必整块落入一个原子）
  const atomImage: Array<number | undefined> = new Array(ipAtoms.length).fill(undefined)
  ipAtoms.forEach((atom, i) => {
    const mi = atomMapping[i]
    if (mi === undefined) return
    const translatedStart = (atom.start + mappings[mi].delta) >>> 0
    atomImage[i] = findAtomIndexAt(ipAtoms2, translatedStart)
  })

  const ipIdx = containedIndices(ipAtoms, target.ipStart, target.ipEnd)
  const portIdx = containedIndices(portAtoms, target.portStart, target.portEnd)
  const protoIdx = protocolDimIndices(target.protocol)

  const categoryKeys: Record<NatPathCategory, Set<string>> = {
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
    // 目标完全落在映射源网段内（evaluateNatPath 校验保证），目标原子必有转换后像
    const img = atomImage[ip]
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`
        const pos1 = owner1.get(key)
        let category: NatPathCategory
        if (pos1 === undefined) {
          category = 'blocked-stage1'
          addToGroup('b1|m', key)
        } else if (!allowSet1.has(active1[pos1].action)) {
          category = 'blocked-stage1'
          addToGroup(`b1|${pos1}`, key)
        } else {
          // 通过前级：源地址按主机位一一转换后以转换后地址进入后级重放
          const pos2 = img === undefined ? undefined : owner2.get(`${img}.${port}.${proto}`)
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

  /** 由单元 key 生成代表报文；translated=true 时附带按主机位转换后的源地址 */
  const packetOf = (key: string, translated: boolean): NatPathPacket => {
    const { ip } = decodeCellKey(key)
    const base = packetFromKey(key, ipAtoms, portAtoms)
    let translatedIp: string | null = null
    if (translated) {
      const mi = atomMapping[ip]
      if (mi !== undefined) {
        translatedIp = intToIpv4((exampleIp(ipAtoms[ip]) + mappings[mi].delta) >>> 0)
      }
    }
    return { ...base, translatedIp }
  }

  /** 重放一个单元的两级轨迹（用于类别代表报文的轨迹与转换后地址标注） */
  const traceOfKey = (key: string): NatPathExample => {
    const pos1 = owner1.get(key)
    const entered = pos1 !== undefined && allowSet1.has(active1[pos1].action)
    let stage2: TandemRuleRef | null = null
    if (entered) {
      const { ip, port, proto } = decodeCellKey(key)
      const img = atomImage[ip]
      const pos2 = img === undefined ? undefined : owner2.get(`${img}.${port}.${proto}`)
      stage2 = pos2 === undefined ? null : makeRuleRef(active2[pos2])
    }
    return {
      ...packetOf(key, entered),
      stage1: pos1 === undefined ? null : makeRuleRef(active1[pos1]),
      enteredStage2: entered,
      stage2,
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

  const buildGroup = (tag: string, keys: Set<string>): NatPathTraceGroup => {
    const parts = tag.split('|')
    const category: NatPathCategory =
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

  const groupsByCategory = new Map<NatPathCategory, NatPathTraceGroup[]>()
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

  const buildCategory = (category: NatPathCategory): NatPathCategorySummary => {
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

  const categories: Record<NatPathCategory, NatPathCategorySummary> = {
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
 * 任一错误都阻止分析；全部通过后执行带源地址转换的两级重放。
 * 后级 JSON 与「粘贴 JSON 导入」同格式（数组 / { rules } / { entries }）；
 * 其中的非法规则、停用规则（enabled=false）按既有语义保留并排除。
 * 目标必须完全落在映射源网段内，否则存在转换结果未定义的报文，整体报错。
 */
export function evaluateNatPath(
  stage1Rules: RuleInput[],
  form: NatPathFormInput,
  now: Date = new Date(),
): NatPathOutcome {
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

  const { mappings, errors: mappingErrors } = parseNatMappings(form.mappingText)
  errors.push(...mappingErrors)

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

  // 目标必须完全落在映射源网段内（映射本身合法时才检查，避免重复报错）
  if (target && mappings.length > 0 && mappingErrors.length === 0) {
    const uncovered = firstUncoveredIp(mappings, target.ipStart, target.ipEnd)
    if (uncovered !== null) {
      errors.push(
        `目标 ${target.cidrText} 未完全落在映射源网段内：` +
          `${intToIpv4(uncovered)} 起的地址不在任何映射源网段中，无法确定其转换后地址`,
      )
    }
  }

  if (errors.length > 0 || !target) return { ok: false, errors }
  return {
    ok: true,
    result: analyzeNatPath(stage1Rules, stage2Rules, allow1, allow2, mappings, target, now),
  }
}
