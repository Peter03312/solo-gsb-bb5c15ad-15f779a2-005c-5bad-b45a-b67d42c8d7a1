/**
 * 首命中规则审计台 —— 类型定义
 *
 * 流量空间为三个维度的笛卡尔积：
 *   源 IPv4（CIDR 划分的原子块）× 源端口（区间边界划分的原子段）× 协议
 * 每条规则声明一个长方体区域；按列表顺序，首个覆盖某单元的规则即该单元的命中者。
 */

export type Protocol = 'TCP' | 'UDP' | 'ANY'
export type Action = string

/** UI / 导入中的规则原始形态 */
export interface RuleInput {
  id: string
  name: string
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  action: string
  enabled: boolean
}

/** 校验通过后的规范规则 */
export interface NormalizedRule {
  id: string
  name: string
  index: number
  ipStart: number
  ipEnd: number
  prefix: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  action: Action
  enabled: boolean
}

export interface InvalidRule {
  id: string
  index: number
  name: string
  errors: string[]
  raw: {
    cidr: string
    portStart: string | number
    portEnd: string | number
    protocol: string
    action: string
    enabled: boolean
  }
}

/** 由 CIDR 边界递归切割得到的 IP 原子块（始终对齐某个 CIDR 前缀） */
export interface IpAtom {
  start: number
  end: number
  prefix: number
}

export interface PortAtom {
  start: number
  end: number
}

export type StatusLevel =
  | 'reachable'
  | 'partial-shadowed'
  | 'fully-shadowed'
  | 'invalid'
  | 'disabled'
  | 'empty'

/** 遮蔽来源：单个单元可同时被多条更早的规则覆盖（共同覆盖） */
export interface ShadowSource {
  ruleIndex: number
  ruleName: string
  action: Action
  /** 该来源在此规则上贡献的单元数 */
  cells: number
}

/** 可复现的示例报文 */
export interface ExamplePacket {
  srcIp: string
  srcPort: number
  protocol: Exclude<Protocol, 'ANY'>
  matchedRuleIndex: number
  matchedRuleName: string
  action: Action
  /** reachable = 命中当前规则；shadowed = 命中的是更早的遮蔽规则 */
  kind: 'reachable' | 'shadowed'
}

/** 有效区域中按协议合并后的展示块 */
export interface RegionGroup {
  protocol: Exclude<Protocol, 'ANY'>
  cidrs: string[]
  portRanges: Array<{ start: number; end: number }>
  /** 该组覆盖的报文空间大小（IP 数 × 端口数） */
  size: number
}

/** 精确区域中的一行：一段连续端口 × 一组规范 CIDR（该区域是二者的笛卡尔积） */
export interface ExactRegionRow {
  portStart: number
  portEnd: number
  cidrs: string[]
  /** 该行的报文空间大小（CIDR 地址数合计 × 端口数） */
  size: number
}

/** 某个具体协议下的精确区域：若干互斥的 端口段 × CIDR 列表 行 */
export interface ExactRegionGroup {
  protocol: Exclude<Protocol, 'ANY'>
  rows: ExactRegionRow[]
  /** 各行大小之和，与单元级统计精确一致 */
  size: number
}

/** 完全遮蔽规则的“最小解释集”中的一条入选前序规则 */
export interface MinExplanationMember {
  ruleIndex: number
  ruleName: string
  action: Action
  /** 该规则覆盖的目标规则声明单元总数 */
  coveredCells: number
  /** 集合内仅由该规则覆盖的单元数——它相对解释集不可替代的部分（必 ≥ 1） */
  uniqueCells: number
  /** uniqueCells 中字典序最小单元的代表报文；matchedRule* 为该单元的真实首命中规则 */
  representative: ExamplePacket
}

/**
 * 最小解释集：在前序合法启用规则中，能联合覆盖一条完全遮蔽规则
 * **全部声明单元**的基数最少子集；同基数时按规则序号数组字典序取唯一结果。
 */
export interface MinExplanation {
  /** 参与求解的候选数：与目标规则声明单元有交集的前序合法启用规则条数 */
  candidateCount: number
  /** 精确求解上限：候选数超过它则跳过，绝不用贪心近似冒充最优 */
  exactLimit: number
  /** true = 候选过多，未计算（members 恒为空、coveredCells 恒为 0） */
  skipped: boolean
  /** 目标规则的声明单元总数 */
  declaredCells: number
  /** 集合联合覆盖的单元数；精确求解时恒等于 declaredCells */
  coveredCells: number
  members: MinExplanationMember[]
}

export interface AuditEntry {
  kind: 'valid'
  id: string
  index: number
  name: string
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  action: Action
  enabled: boolean

  /**
   * 仅对启用规则计算；停用规则恒为 'disabled'，其余字段保留声明空间信息，
   * 但不参与首命中分析（区域恒空、统计不计入有效 / 声明空间）。
   */
  status: Exclude<StatusLevel, 'invalid'>
  /** 声明区域的报文空间大小 */
  declaredSize: number
  /** 首条命中语义下真正落到本规则的大小；停用规则恒为 0 */
  effectiveSize: number
  effectiveRatio: number

  region: RegionGroup[]
  shadowSources: ShadowSource[]
  /** 该规则被遮蔽的单元数（一个单元可被多个来源共同遮蔽，此为去重后的单元数） */
  blockedCells: number
  declaredCells: number
  effectiveCells: number

  reachableExample: ExamplePacket | null
  shadowedExamples: ExamplePacket[]
  /** 完全遮蔽且没有任何单条前序规则能独立遮蔽全部单元（即多规则共同覆盖） */
  collectiveCover: boolean
  /**
   * 最小解释集：仅完全遮蔽规则计算，其余状态恒为 null。
   * 候选来源（与其声明单元有交集的前序合法启用规则）超过精确上限时，
   * 显式标记 skipped=true，不输出任何贪心近似结果。
   */
  minExplanation: MinExplanation | null
}

export interface AuditInvalidEntry {
  kind: 'invalid'
  id: string
  index: number
  name: string
  errors: string[]
  raw: InvalidRule['raw']
}

export type AuditResultEntry = AuditEntry | AuditInvalidEntry

export interface AuditStats {
  total: number
  invalid: number
  disabled: number
  reachable: number
  partial: number
  fullyShadowed: number
  totalDeclaredSize: number
  totalEffectiveSize: number
}

export interface AuditReport {
  generatedAt: string
  stats: AuditStats
  entries: AuditResultEntry[]
}
