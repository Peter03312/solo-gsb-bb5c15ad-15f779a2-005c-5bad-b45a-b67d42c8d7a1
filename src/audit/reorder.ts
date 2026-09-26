/**
 * 调序影响预览。
 *
 * 拖拽只产生一个“候选顺序”而不立即改动规则；本模块分别对当前顺序与候选
 * 顺序执行既有审计（audit），并按规则 id 对齐两份结果。由于两次审计的
 * 规则集合完全相同（仅排列不同），IP 原子块 / 端口原子段的划分也完全
 * 相同，因此可以在同一套原子空间上逐单元比较“首个命中者”：
 *
 *   - 命中规则的 id 变化 → 归属转移（reassignment）
 *   - 旧 / 新命中规则动作不同 → 该流量的首命中动作发生变化，给出一个
 *     确定性、可复现的样例报文（IP、端口、协议）及前后命中规则与动作
 *
 * 非法规则继续按既有语义排除：不参与原子空间构建与命中计算，只在逐规则
 * 对比中展示其序号变化。
 */
import {
  activeRules,
  audit,
  atomCellSize,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
} from './engine'
import { intToIpv4 } from './iputil'
import type {
  AuditReport,
  AuditResultEntry,
  Protocol,
  RuleInput,
  StatusLevel,
} from './types'

const CONCRETE: Array<Extract<Protocol, 'TCP' | 'UDP'>> = ['TCP', 'UDP']

/** 可复现的样例报文（与 ExamplePacket 同构，独立定义以便解耦） */
export interface ReorderPacket {
  srcIp: string
  srcPort: number
  protocol: Extract<Protocol, 'TCP' | 'UDP'>
}

/** 一组首命中归属发生转移的流量 */
export interface TrafficChange {
  packet: ReorderPacket
  /** 该组变化覆盖的报文空间大小（IP 数 × 端口数，协议按单元计） */
  size: number
  /** 组内合并的原子单元数 */
  cells: number
  oldRuleId: string
  oldIndex: number
  oldName: string
  oldAction: string
  newRuleId: string
  newIndex: number
  newName: string
  newAction: string
  /** 首命中动作是否随归属一起变化（false = 仅易主，动作相同） */
  actionChanged: boolean
}

/** 受影响的规则：序号、状态或有效报文空间发生变化 */
export interface ReorderRuleView {
  id: string
  name: string
  oldIndex: number
  newIndex: number
  /** 列表位置是否移动 */
  moved: boolean
  oldStatus: StatusLevel
  newStatus: StatusLevel
  oldEffectiveSize: number
  newEffectiveSize: number
  sizeDelta: number
  /** 状态或有效空间是否变化（false = 仅序号变化，无审计差异） */
  auditChanged: boolean
}

export interface ReorderPreview {
  rules: ReorderRuleView[]
  actionChanges: TrafficChange[]
  sameActionChanges: TrafficChange[]
  /** 存在序号或审计变化的规则数 */
  affectedRuleCount: number
  /** 首命中归属发生转移的总报文空间 */
  totalReassignedSize: number
  /** 是否有任何实际差异（状态 / 有效空间 / 流量归属） */
  hasDifference: boolean
}

function exampleIpForAtom(start: number, end: number): number {
  const size = end - start + 1
  // 与引擎 makePacket 的选点保持一致：块内至少 4 个地址时取第 2 个
  return size >= 4 ? (start + 1) >>> 0 : start
}

function decodeCellKey(key: string): [number, number, number] {
  const [ip, port, proto] = key.split('.').map(Number)
  return [ip, port, proto]
}

function byId(entries: AuditResultEntry[]): Map<string, AuditResultEntry> {
  const map = new Map<string, AuditResultEntry>()
  for (const e of entries) map.set(e.id, e)
  return map
}

function entryStatus(e: AuditResultEntry | undefined): StatusLevel {
  if (!e) return 'invalid'
  return e.kind === 'invalid' ? 'invalid' : e.status
}

function entryEffective(e: AuditResultEntry | undefined): number {
  return e && e.kind === 'valid' ? e.effectiveSize : 0
}

function entryName(e: AuditResultEntry | undefined, fallback: RuleInput): string {
  if (e && (e.kind === 'valid' || e.kind === 'invalid')) return e.name
  return fallback.name.trim() || '(未命名规则)'
}

/** 对规则数组做一次移动：把 from 位置的规则移到 to 位置（与 UI 的 splice 语义一致） */
export function movedRules(rules: RuleInput[], from: number, to: number): RuleInput[] {
  if (from === to || from < 0 || to < 0 || from >= rules.length || to >= rules.length) {
    return rules
  }
  const next = [...rules]
  const [m] = next.splice(from, 1)
  next.splice(to, 0, m)
  return next
}

/**
 * 计算调序影响预览。
 * @param current  当前规则顺序（弹窗确认前不会被修改）
 * @param candidate 拖拽产生的候选顺序
 */
export function previewReorder(
  current: RuleInput[],
  candidate: RuleInput[],
): ReorderPreview {
  const oldReport: AuditReport = audit(current)
  const newReport: AuditReport = audit(candidate)

  // 参与首命中分析的是合法且已启用的规则；非法 / 停用规则只在逐规则对比中展示序号变化
  const oldValid = activeRules(current)
  const newValid = activeRules(candidate)

  // 规则集合相同（仅排列不同），两种顺序下的原子划分必然相同：
  // IP 划分是所有声明范围的最长前缀细分，端口划分是所有端点的切分，均与顺序无关。
  const ipAtoms = buildIpAtoms(oldValid)
  const portAtoms = buildPortAtoms(oldValid)
  const oldOwner = buildOwnerMap(oldValid, ipAtoms, portAtoms)
  const newOwner = buildOwnerMap(newValid, ipAtoms, portAtoms)

  // 按 (旧命中者位置, 新命中者位置) 聚合归属转移的单元
  const groups = new Map<string, { keys: Set<string>; oldPos: number; newPos: number }>()
  for (const [key, oldPos] of oldOwner) {
    const newPos = newOwner.get(key)
    if (newPos === undefined) continue // 被某规则声明但新顺序无人拥有：不可能（声明集合不变）
    if (oldValid[oldPos].id === newValid[newPos].id) continue
    const gk = `${oldPos}>${newPos}`
    let g = groups.get(gk)
    if (!g) {
      g = { keys: new Set(), oldPos, newPos }
      groups.set(gk, g)
    }
    g.keys.add(key)
  }
  // 旧顺序无人拥有、新顺序有人拥有同样不可能（任一顺序的覆盖集合相同）。

  const changes: TrafficChange[] = []
  for (const g of groups.values()) {
    const oldRule = oldValid[g.oldPos]
    const newRule = newValid[g.newPos]
    let size = 0
    for (const key of g.keys) {
      const [ip, port] = decodeCellKey(key)
      size += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    // 确定性代表单元：字典序最小（与引擎示例报文选点规则一致）
    const sampleKey = [...g.keys].sort()[0]
    const [ipIdx, portIdx, protoIdx] = decodeCellKey(sampleKey)
    const ipAtom = ipAtoms[ipIdx]
    changes.push({
      packet: {
        srcIp: intToIpv4(exampleIpForAtom(ipAtom.start, ipAtom.end)),
        srcPort: portAtoms[portIdx].start,
        protocol: CONCRETE[protoIdx],
      },
      size,
      cells: g.keys.size,
      oldRuleId: oldRule.id,
      oldIndex: oldRule.index,
      oldName: oldRule.name,
      oldAction: oldRule.action,
      newRuleId: newRule.id,
      newIndex: newRule.index,
      newName: newRule.name,
      newAction: newRule.action,
      actionChanged: oldRule.action !== newRule.action,
    })
  }

  changes.sort((a, b) => {
    if (a.actionChanged !== b.actionChanged) return a.actionChanged ? -1 : 1
    return (
      b.size - a.size ||
      a.oldIndex - b.oldIndex ||
      a.newIndex - b.newIndex
    )
  })

  // ---- 逐规则对齐（按 id）：序号 / 状态 / 有效空间 ----
  const oldEntries = byId(oldReport.entries)
  const newEntries = byId(newReport.entries)
  const oldIndexById = new Map(current.map((r, i) => [r.id, i]))
  const newIndexById = new Map(candidate.map((r, i) => [r.id, i]))

  const ruleViews: ReorderRuleView[] = []
  for (const rule of current) {
    const oldE = oldEntries.get(rule.id)
    const newE = newEntries.get(rule.id)
    const oldIndex = oldIndexById.get(rule.id) ?? -1
    const newIndex = newIndexById.get(rule.id) ?? -1
    const oldStatus = entryStatus(oldE)
    const newStatus = entryStatus(newE)
    const oldSize = entryEffective(oldE)
    const newSize = entryEffective(newE)
    const moved = oldIndex !== newIndex
    const auditChanged = oldStatus !== newStatus || oldSize !== newSize
    if (moved || auditChanged) {
      ruleViews.push({
        id: rule.id,
        name: entryName(oldE, rule),
        oldIndex,
        newIndex,
        moved,
        oldStatus,
        newStatus,
        oldEffectiveSize: oldSize,
        newEffectiveSize: newSize,
        sizeDelta: newSize - oldSize,
        auditChanged,
      })
    }
  }
  ruleViews.sort((a, b) => a.newIndex - b.newIndex)

  const actionChanges = changes.filter((c) => c.actionChanged)
  const sameActionChanges = changes.filter((c) => !c.actionChanged)
  const totalReassignedSize = changes.reduce((s, c) => s + c.size, 0)
  const hasDifference = changes.length > 0 || ruleViews.some((v) => v.auditChanged)

  return {
    rules: ruleViews,
    actionChanges,
    sameActionChanges,
    affectedRuleCount: ruleViews.length,
    totalReassignedSize,
    hasDifference,
  }
}
