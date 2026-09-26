/**
 * 审计快照对比（只读）。
 *
 * 用户可为当前规则集保存带名称的快照（保存时深拷贝，之后的规则编辑不影响
 * 已存快照）。对任意两个快照生成对比报告：
 *
 *   1. 取两个快照的合法且启用规则（非法 / 停用规则与审计一致地排除），
 *      把**双方**的 CIDR 与端口边界合并切分，得到同一套 IPv4 原子块 ×
 *      端口原子段 × {TCP, UDP} 离散单元空间；
 *   2. 在该合并空间上分别重放两个快照的首命中归属（owner 表）；
 *   3. 对任一快照有首命中者的每个单元逐单元比较，精确分为四类：
 *        - 动作未变        两侧首命中动作一致（命中者可能易主，见下）
 *        - 动作改变        两侧均有首命中者但动作不同
 *        - 由命中变为未命中 旧快照有首命中者、新快照无任何规则覆盖
 *        - 由未命中变为命中 新快照有首命中者、旧快照无任何规则覆盖
 *
 * 两个快照都不覆盖的单元（双方规则声明区域之外）不参与对比。
 * 「动作未变」中首命中规则 id 发生变化的单元单独聚合为「同动作易主」分组，
 * 便于区分真正的规则切换与原地未动。
 *
 * 每个类别与每个下钻分组都给出：报文空间大小、原子单元数、按
 * 「协议 → 连续端口段 × 规范 CIDR 列表」展开的精确区域（复用引擎的
 * buildExactRegions，行大小合计与单元级统计精确一致），以及确定性、
 * 可复制的代表报文（取组内字典序最小单元，选点规则与引擎示例报文一致）。
 *
 * 对比全程只读：不修改当前规则，也不修改任何快照。
 */
import {
  activeRules,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  decodeCellKey,
  firstKey,
  packetFromKey,
  validateRules,
} from './engine'
import type {
  ExactRegionGroup,
  NormalizedRule,
  Protocol,
  RuleInput,
} from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

/** 一份命名快照：保存时刻规则集的深拷贝，之后的编辑不影响它 */
export interface RuleSnapshot {
  id: string
  name: string
  createdAt: string
  rules: RuleInput[]
}

/** 快照的规则构成统计（展示用；非法 / 停用规则不参与对比重放） */
export interface SnapshotRuleStats {
  total: number
  active: number
  invalid: number
  disabled: number
}

/** 为当前规则集创建快照（深拷贝规则，保存后与规则列表互不影响） */
export function createSnapshot(
  name: string,
  rules: RuleInput[],
  now: Date = new Date(),
): RuleSnapshot {
  return {
    id: `snap-${Math.random().toString(36).slice(2, 10)}`,
    name: name.trim(),
    createdAt: now.toISOString(),
    rules: JSON.parse(JSON.stringify(rules)) as RuleInput[],
  }
}

/** 统计快照内规则的构成：总数 / 参与对比的合法启用数 / 非法数 / 停用数 */
export function snapshotRuleStats(snapshot: RuleSnapshot): SnapshotRuleStats {
  const { valid, invalid } = validateRules(snapshot.rules)
  const disabled = valid.filter((r) => !r.enabled).length
  return {
    total: snapshot.rules.length,
    active: valid.length - disabled,
    invalid: invalid.length,
    disabled,
  }
}

// ---------------------------------------------------------------------------
// 对比结果类型
// ---------------------------------------------------------------------------

export type DiffCategory =
  | 'unchanged' // 动作未变
  | 'action-changed' // 动作改变
  | 'became-unmatched' // 由命中变为未命中
  | 'became-matched' // 由未命中变为命中

export const DIFF_CATEGORY_ORDER: DiffCategory[] = [
  'action-changed',
  'became-unmatched',
  'became-matched',
  'unchanged',
]

/** 对某一侧快照首命中规则的引用（规则序号 / 名称 / 动作均取自该快照自身） */
export interface DiffRuleRef {
  index: number
  name: string
  action: string
}

/** 可复制的代表报文 */
export interface DiffPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
}

/** 一个类别内的下钻分组（动作未变类别仅含「同动作易主」分组） */
export interface DiffGroup {
  category: DiffCategory
  /** 旧快照侧首命中规则（旧快照未命中时为 null） */
  before: DiffRuleRef | null
  /** 新快照侧首命中规则（新快照未命中时为 null） */
  after: DiffRuleRef | null
  size: number
  cells: number
  regions: ExactRegionGroup[]
  /** 组内字典序最小单元的确定性代表报文 */
  packet: DiffPacket
}

/** 一个类别的汇总：总量 + 精确区域 + 每协议代表报文 + 下钻分组 */
export interface DiffCategorySummary {
  category: DiffCategory
  size: number
  cells: number
  regions: ExactRegionGroup[]
  /** 每个具体协议至多一个代表报文（TCP / UDP 各一） */
  examples: DiffPacket[]
  groups: DiffGroup[]
}

export interface SnapshotDiffResult {
  generatedAt: string
  base: { id: string; name: string; createdAt: string }
  target: { id: string; name: string; createdAt: string }
  baseStats: SnapshotRuleStats
  targetStats: SnapshotRuleStats
  /** 参与对比的单元总数（任一快照有首命中者的单元） */
  comparedCells: number
  /** 参与对比的报文空间总大小 */
  comparedSize: number
  /** 是否存在任何动作级差异（动作改变 / 命中↔未命中） */
  hasActionDifference: boolean
  /** 是否存在同动作易主（动作未变但首命中规则 id 改变） */
  hasReassignment: boolean
  categories: Record<DiffCategory, DiffCategorySummary>
}

// ---------------------------------------------------------------------------
// 对比主流程
// ---------------------------------------------------------------------------

function makeRuleRef(rule: NormalizedRule): DiffRuleRef {
  return { index: rule.index, name: rule.name, action: rule.action }
}

/**
 * 对比两个快照。base 为旧（基准）快照，target 为新（目标）快照。
 * 纯函数：不修改快照与当前规则。
 */
export function compareSnapshots(
  base: RuleSnapshot,
  target: RuleSnapshot,
  now: Date = new Date(),
): SnapshotDiffResult {
  const baseActive = activeRules(base.rules)
  const targetActive = activeRules(target.rules)

  // 合并原子空间：双方规则的 CIDR / 端口边界共同参与切分，
  // 两个快照在同一套单元上逐一对齐重放首命中。
  const ipAtoms = buildIpAtoms([...baseActive, ...targetActive])
  const portAtoms = buildPortAtoms([...baseActive, ...targetActive])
  const baseOwner = buildOwnerMap(baseActive, ipAtoms, portAtoms)
  const targetOwner = buildOwnerMap(targetActive, ipAtoms, portAtoms)

  // 逐单元分类；类别单元集合 + 分组单元集合（分组键见下）
  const categoryKeys = new Map<DiffCategory, Set<string>>()
  const groupKeys = new Map<string, Set<string>>()
  const addTo = <T>(map: Map<T, Set<string>>, tag: T, key: string) => {
    let set = map.get(tag)
    if (!set) {
      set = new Set()
      map.set(tag, set)
    }
    set.add(key)
  }

  let comparedSize = 0
  for (const [key, basePos] of baseOwner) {
    const targetPos = targetOwner.get(key)
    const baseRule = baseActive[basePos]
    const targetRule = targetPos === undefined ? null : targetActive[targetPos]
    let category: DiffCategory
    let groupTag: string
    if (targetRule === null) {
      category = 'became-unmatched'
      groupTag = `u|${basePos}`
    } else if (baseRule.action !== targetRule.action) {
      category = 'action-changed'
      groupTag = `c|${basePos}|${targetPos}`
    } else {
      category = 'unchanged'
      // 动作未变类别只对「同动作易主」的单元建下钻分组；
      // 命中者与动作都未变的单元不建组（数量可能极大且无变化可查）
      if (baseRule.id !== targetRule.id) groupTag = `r|${basePos}|${targetPos}`
      else groupTag = ''
    }
    addTo(categoryKeys, category, key)
    if (groupTag) addTo(groupKeys, groupTag, key)
    const { ip, port } = decodeCellKey(key)
    comparedSize += atomCellSize(ipAtoms[ip], portAtoms[port])
  }
  // 旧快照未命中、新快照命中的单元（反向遍历新快照 owner 表补齐）
  for (const [key, targetPos] of targetOwner) {
    if (baseOwner.has(key)) continue
    addTo(categoryKeys, 'became-matched', key)
    addTo(groupKeys, `m|${targetPos}`, key)
    const { ip, port } = decodeCellKey(key)
    comparedSize += atomCellSize(ipAtoms[ip], portAtoms[port])
  }

  const packetOf = (key: string): DiffPacket =>
    packetFromKey(key, ipAtoms, portAtoms) as DiffPacket

  const summarizeKeys = (keys: Set<string>) => {
    let size = 0
    for (const key of keys) {
      const { ip, port } = decodeCellKey(key)
      size += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    return size
  }

  // 下钻分组：解析分组键 → 前后规则引用；按空间大小降序、再按前后序号排序
  const buildGroup = (tag: string, keys: Set<string>): DiffGroup => {
    const parts = tag.split('|')
    const category: DiffCategory =
      parts[0] === 'u'
        ? 'became-unmatched'
        : parts[0] === 'm'
          ? 'became-matched'
          : parts[0] === 'c'
            ? 'action-changed'
            : 'unchanged'
    const before =
      parts[0] === 'u' || parts[0] === 'c' || parts[0] === 'r'
        ? makeRuleRef(baseActive[Number(parts[1])])
        : null
    const afterIdx = parts[0] === 'm' ? parts[1] : parts[0] === 'u' ? null : parts[2]
    const after = afterIdx === null ? null : makeRuleRef(targetActive[Number(afterIdx)])
    return {
      category,
      before,
      after,
      size: summarizeKeys(keys),
      cells: keys.size,
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      packet: packetOf(firstKey(keys)),
    }
  }

  const groupsByCategory = new Map<DiffCategory, DiffGroup[]>()
  for (const [tag, keys] of groupKeys) {
    const group = buildGroup(tag, keys)
    let list = groupsByCategory.get(group.category)
    if (!list) {
      list = []
      groupsByCategory.set(group.category, list)
    }
    list.push(group)
  }
  const groupSortKey = (ref: DiffRuleRef | null) => ref?.index ?? Number.MAX_SAFE_INTEGER
  for (const list of groupsByCategory.values()) {
    list.sort(
      (a, b) =>
        b.size - a.size ||
        groupSortKey(a.before) - groupSortKey(b.before) ||
        groupSortKey(a.after) - groupSortKey(b.after),
    )
  }

  const buildCategory = (category: DiffCategory): DiffCategorySummary => {
    const keys = categoryKeys.get(category) ?? new Set<string>()
    // 代表报文：每个具体协议取该类别内字典序最小单元（确定性、可复现）
    const firstByProto = new Map<number, string>()
    for (const key of keys) {
      const { proto } = decodeCellKey(key)
      const cur = firstByProto.get(proto)
      if (cur === undefined || key < cur) firstByProto.set(proto, key)
    }
    return {
      category,
      size: summarizeKeys(keys),
      cells: keys.size,
      regions: buildExactRegions(keys, ipAtoms, portAtoms),
      examples: [0, 1]
        .map((proto) => firstByProto.get(proto))
        .filter((k): k is string => k !== undefined)
        .map(packetOf),
      groups: groupsByCategory.get(category) ?? [],
    }
  }

  const categories = {
    unchanged: buildCategory('unchanged'),
    'action-changed': buildCategory('action-changed'),
    'became-unmatched': buildCategory('became-unmatched'),
    'became-matched': buildCategory('became-matched'),
  }

  const comparedCells =
    categories.unchanged.cells +
    categories['action-changed'].cells +
    categories['became-unmatched'].cells +
    categories['became-matched'].cells

  return {
    generatedAt: now.toISOString(),
    base: { id: base.id, name: base.name, createdAt: base.createdAt },
    target: { id: target.id, name: target.name, createdAt: target.createdAt },
    baseStats: snapshotRuleStats(base),
    targetStats: snapshotRuleStats(target),
    comparedCells,
    comparedSize,
    hasActionDifference:
      categories['action-changed'].cells > 0 ||
      categories['became-unmatched'].cells > 0 ||
      categories['became-matched'].cells > 0,
    hasReassignment: categories.unchanged.groups.length > 0,
    categories,
  }
}

// ---------------------------------------------------------------------------
// 快照本地持久化（localStorage；不可用时静默退化为仅内存）
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'first-hit-audit.snapshots.v1'

/** 从 localStorage 读取快照列表；读取失败 / 数据损坏时返回空列表 */
export function loadSnapshots(): RuleSnapshot[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const data: unknown = JSON.parse(raw)
    if (!Array.isArray(data)) return []
    const out: RuleSnapshot[] = []
    for (const item of data) {
      if (!item || typeof item !== 'object') continue
      const o = item as Record<string, unknown>
      if (
        typeof o.id === 'string' &&
        typeof o.name === 'string' &&
        typeof o.createdAt === 'string' &&
        Array.isArray(o.rules)
      ) {
        out.push({
          id: o.id,
          name: o.name,
          createdAt: o.createdAt,
          rules: o.rules as RuleInput[],
        })
      }
    }
    return out
  } catch {
    return []
  }
}

/** 把快照列表写入 localStorage；存储不可用 / 超限时静默忽略（内存中仍保留） */
export function persistSnapshots(snapshots: RuleSnapshot[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshots))
  } catch {
    // 隐私模式 / 配额超限等场景：快照仅在本次会话内存中保留
  }
}
