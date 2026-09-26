/**
 * 审计例外清单（audit exceptions）。
 *
 * 用户可为「指定规则 × 指定问题类型（完全遮蔽 / 部分遮蔽）」登记一条例外，
 * 声明该例外适用的报文范围：源 IPv4 CIDR × 源端口区间 × 协议（ANY 同时覆盖
 * TCP / UDP），并附带到期时间与说明。
 *
 * 系统把例外声明范围与该规则**当前实际被遮蔽（shadowed）的报文区域**做
 * 逐原子单元的**精确交集**：
 *
 *   - 交集中的单元标记为「已豁免」；多条例外重叠时按并集去重，不重复计数；
 *   - 被遮蔽区域中未被任何有效例外覆盖的单元仍列为「待处理」；
 *   - 例外声明范围落在规则遮蔽区域之外的部分不产生任何豁免（零覆盖），
 *     该例外保留在清单中并明确提示「与当前遮蔽区域无交集」。
 *
 * 只有**字段合法、未到期、且目标规则当前确实存在对应问题类型**的例外才
 * 参与豁免；非法条目（CIDR / 端口 / 协议 / 到期时间 / 说明校验失败）、
 * 已过期条目、目标规则缺失 / 非法 / 停用或问题类型不匹配的条目都会被
 * 明确标注原因且完全不参与豁免计算。
 *
 * 本模块是审计引擎之上的**只读附加层**：不改动 `audit()` 的任何结论与统计，
 * 例外边界会追加进 IPv4 / 端口原子切分，因此交集精确到单元，不做
 * 「声明范围相交即整体豁免」的近似。规则编辑后由 UI 重新调用本模块即可
 * 自动重算（原子空间随规则重建）。
 */
import {
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  packetFromKey,
  PROTO_INDEX,
  validatePortRange,
  validateRules,
} from './engine'
import { parseCidrStrict } from './iputil'
import type {
  ExactRegionGroup,
  Protocol,
  RuleInput,
} from './types'

export type IssueType = 'fully-shadowed' | 'partial-shadowed'

export const ISSUE_TYPES: IssueType[] = ['fully-shadowed', 'partial-shadowed']

export const ISSUE_TYPE_TEXT: Record<IssueType, string> = {
  'fully-shadowed': '完全遮蔽',
  'partial-shadowed': '部分遮蔽',
}

/** UI / 导入中的例外原始形态（端口与到期时间允许字符串） */
export interface ExceptionInput {
  id: string
  /** 目标规则 id（规则跨编辑的稳定标识，不使用会随排序变化的序号） */
  ruleId: string
  issueType: string
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  /** 到期时间文本：空字符串表示永久；推荐 ISO 8601（如 2026-12-31T23:59Z） */
  expiresAt: string
  notes: string
}

/** 校验通过后的规范例外（expiresAtMs === null 表示永久有效） */
export interface NormalizedException {
  id: string
  ruleId: string
  issueType: IssueType
  ipStart: number
  ipEnd: number
  prefix: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  /** null = 永久；否则为毫秒时间戳，当前时间晚于它即视为过期 */
  expiresAtMs: number | null
  expiresAtText: string
  notes: string
}

export type InvalidExceptionReason =
  | 'invalid' // 字段校验失败
  | 'expired' // 曾经过期，不参与豁免
  | 'rule-missing' // 目标规则已不存在
  | 'rule-invalid' // 目标规则当前非法、不参与分析
  | 'rule-disabled' // 目标规则当前停用、不参与分析
  | 'issue-mismatch' // 目标规则当前不存在该问题类型（如已变为可达 / 另一种遮蔽）

/** 不参与豁免的例外：非法 / 过期 / 目标无效 / 问题不匹配，均明确列出原因 */
export interface InvalidException {
  kind: 'invalid-exception'
  id: string
  /** 在输入清单中的原始下标（用于稳定排序与 UI 对照） */
  order: number
  ruleId: string
  issueType: IssueType | null
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  expiresAt: string
  notes: string
  reason: InvalidExceptionReason
  errors: string[]
  /** reason 对应的人类可读说明（UI 直接展示） */
  message: string
}

/** 已豁免区域中的确定性代表报文（可一键复制复现） */
export interface ExceptionPacket {
  srcIp: string
  srcPort: number
  protocol: Exclude<Protocol, 'ANY'>
}

/** 一条有效例外在某条规则遮蔽区域上的实际覆盖（精确交集结果） */
export interface ExceptionCoverage {
  exceptionId: string
  issueType: IssueType
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  expiresAtMs: number | null
  expiresAtText: string
  notes: string
  /** 与该规则实际遮蔽区域的交集大小（报文空间）；为 0 表示例外范围未落在遮蔽区域内 */
  coveredSize: number
  coveredCells: number
  /** 交集的精确区域（协议 → 端口段 × 规范 CIDR 行） */
  regions: ExactRegionGroup[]
  /** 交集中字典序最小单元的代表报文；coveredCells=0 时为 null */
  representative: ExceptionPacket | null
  /** 覆盖范围与规则当前实际遮蔽区域无交集（合法但本次不豁免任何报文） */
  noOverlap: boolean
}

/** 规则当前实际存在的问题类型（用于与例外声明的问题类型比对） */
export type RuleIssueStatus =
  | 'reachable'
  | 'partial-shadowed'
  | 'fully-shadowed'

/** 一条规则的遮蔽区域在例外清单下的豁免分解 */
export interface RuleExemption {
  kind: 'rule'
  ruleId: string
  ruleIndex: number
  ruleName: string
  action: string
  /** 规则当前实际状态（仅含 reachable / partial / fully 三种参与分析的状态） */
  ruleStatus: RuleIssueStatus
  declaredSize: number
  /** 当前实际被遮蔽的报文空间大小（与审计结论一致） */
  blockedSize: number
  blockedCells: number
  /** 被有效例外覆盖（多条例外并集去重）的遮蔽空间 */
  exemptSize: number
  exemptCells: number
  /** 仍需处理的遮蔽空间 = blockedSize - exemptSize */
  pendingSize: number
  pendingCells: number
  exemptRatio: number
  /** 全部遮蔽单元已豁免 */
  fullyExempt: boolean
  /** 参与本规则豁免的有效例外（按覆盖大小降序、同大小按 id 排序，确定可复现） */
  coverages: ExceptionCoverage[]
  /** 已豁免区域（所有有效例外覆盖的并集） */
  exemptRegions: ExactRegionGroup[]
  exemptRepresentative: ExceptionPacket | null
  /** 待处理区域（遮蔽区域减去豁免并集） */
  pendingRegions: ExactRegionGroup[]
  pendingRepresentative: ExceptionPacket | null
}

export type ExemptionEntry = RuleExemption | InvalidException

export interface ExemptionStats {
  /** 清单条例总数（含非法 / 过期等不参与豁免的条目） */
  totalExceptions: number
  /** 字段非法 */
  invalidCount: number
  /** 已过期 */
  expiredCount: number
  /** 目标规则缺失 / 非法 / 停用 */
  targetBadCount: number
  /** 问题类型不匹配 */
  mismatchCount: number
  /** 合法、未过期且目标问题存在的有效例外数（含零覆盖） */
  activeCount: number
  /** 有效但与当前遮蔽区域无交集（零覆盖）的例外数 */
  noOverlapCount: number
  /** 存在遮蔽区域的规则数（完全遮蔽 + 部分遮蔽） */
  issueRuleCount: number
  /** 遮蔽区域已全部豁免的规则数 */
  fullyExemptRuleCount: number
  /** 部分豁免（仍有待处理区域）的规则数 */
  partiallyExemptRuleCount: number
  /** 全部规则遮蔽空间合计 */
  totalBlockedSize: number
  /** 已豁免遮蔽空间合计 */
  totalExemptSize: number
  /** 待处理遮蔽空间合计 */
  totalPendingSize: number
}

export interface ExemptionReport {
  generatedAt: string
  evaluatedAt: string
  entries: ExemptionEntry[]
  stats: ExemptionStats
}

// ---------------------------------------------------------------------------
// 校验与规范化
// ---------------------------------------------------------------------------

function makeId(): string {
  return Math.random().toString(36).slice(2, 10)
}

export function newExceptionInput(
  ruleId = '',
  issueType: IssueType = 'fully-shadowed',
): ExceptionInput {
  return {
    id: makeId(),
    ruleId,
    issueType,
    cidr: '0.0.0.0/0',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    expiresAt: '',
    notes: '',
  }
}

/** 归一化问题类型文本：接受英文枚举与常见中文写法 */
export function normalizeIssueType(text: string): IssueType | null {
  const t = text.trim().toLowerCase().replace(/[\s_]/g, '-')
  if (
    t === 'fully-shadowed' ||
    t === 'fully' ||
    t === 'full-shadowed' ||
    t === '完全遮蔽'
  ) {
    return 'fully-shadowed'
  }
  if (
    t === 'partial-shadowed' ||
    t === 'partial' ||
    t === '部分遮蔽'
  ) {
    return 'partial-shadowed'
  }
  return null
}

/**
 * 解析到期时间文本。
 *   - 空串 → null（永久）；
 *   - `YYYY-MM-DD` → 当天 23:59:59.999 UTC（便于只填日期的 JSON 导入）；
 *   - 其余按 Date 解析，要求可解析且非 NaN；不带时区的日期时间按 UTC 解释
 *     （本工具全部时间以 UTC 存储与比较，避免浏览器时区差异）。
 */
export function parseExpiry(text: string): { ms: number | null; iso: string } | { error: string } {
  const raw = text.trim()
  if (raw === '') return { ms: null, iso: '' }
  let value: number
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    value = Date.parse(`${raw}T23:59:59.999Z`)
  } else if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d{1,3})?$/.test(raw)) {
    // datetime-local 等不带时区的写法：按 UTC 解释（补上 Z）
    value = Date.parse(`${raw.toUpperCase().replace(' ', 'T')}Z`)
  } else {
    value = Date.parse(raw)
  }
  if (Number.isNaN(value)) {
    return {
      error: `到期时间无法解析：“${text}”，请使用 YYYY-MM-DD 或 ISO 8601（如 2026-12-31T23:59Z）`,
    }
  }
  return { ms: value, iso: new Date(value).toISOString() }
}

/** 浏览器 datetime-local 输入值（无时区）→ UTC ISO；空串表示永久 */
export function expiryFromDatetimeLocal(value: string): string {
  if (!value) return ''
  const parsed = parseExpiry(value)
  return 'iso' in parsed ? parsed.iso : ''
}

/** UTC ISO 到期时间 → datetime-local 需要的无时区字符串；永久返回空串 */
export function expiryToDatetimeLocal(iso: string): string {
  if (!iso) return ''
  const ms = Date.parse(iso)
  if (Number.isNaN(ms)) return ''
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(
    d.getUTCHours(),
  )}:${pad(d.getUTCMinutes())}`
}

/** 到期时间展示：永久 / UTC 标准串；无法解析时原样返回（非法条目展示原文） */
export function formatExpiry(iso: string): string {
  const raw = iso.trim()
  if (!raw) return '永久'
  const ms = Date.parse(raw)
  if (Number.isNaN(ms)) return raw
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

export interface ExceptionValidation {
  exception: NormalizedException | null
  errors: string[]
}

/** 与规则同一套严格标准校验单条例外（此处不判断到期，过期在评估时判定） */
export function validateException(input: ExceptionInput): ExceptionValidation {
  const errors: string[] = []

  const ruleId = input.ruleId.trim()
  if (!ruleId) errors.push('必须指定适用规则')

  const issueType = normalizeIssueType(input.issueType)
  if (!issueType) {
    errors.push(`问题类型必须为完全遮蔽 / 部分遮蔽，收到 “${input.issueType}”`)
  }

  let cidr: ReturnType<typeof parseCidrStrict> | null = null
  if (!input.cidr.trim()) {
    errors.push('适用 CIDR 不能为空')
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

  let expiresAtMs: number | null = null
  let expiresAtText = ''
  const expiry = parseExpiry(input.expiresAt)
  if ('error' in expiry) {
    errors.push(expiry.error)
  } else {
    expiresAtMs = expiry.ms
    expiresAtText = expiry.iso
  }

  const notes = input.notes.trim()
  if (!notes) errors.push('例外说明不能为空')

  if (errors.length > 0 || !cidr || issueType === null || protocol === null) {
    return { exception: null, errors }
  }

  return {
    exception: {
      id: input.id || makeId(),
      ruleId,
      issueType,
      ipStart: cidr.start,
      ipEnd: cidr.end,
      prefix: cidr.prefix,
      cidrText: cidr.canonical,
      portStart: ports.portStart,
      portEnd: ports.portEnd,
      protocol,
      expiresAtMs,
      expiresAtText,
      notes,
    },
    errors: [],
  }
}

// ---------------------------------------------------------------------------
// 主评估流程
// ---------------------------------------------------------------------------

interface RuleRuntimeLite {
  ruleId: string
  ruleIndex: number
  ruleName: string
  action: string
  declaredKeys: Set<string>
  ownedKeys: Set<string>
}

function invalidEntry(
  input: ExceptionInput,
  order: number,
  issueType: IssueType | null,
  reason: InvalidExceptionReason,
  errors: string[],
  message: string,
): InvalidException {
  return {
    kind: 'invalid-exception',
    id: input.id,
    order,
    ruleId: input.ruleId.trim(),
    issueType,
    cidr: input.cidr,
    portStart: input.portStart,
    portEnd: input.portEnd,
    protocol: input.protocol,
    expiresAt: input.expiresAt,
    notes: input.notes,
    reason,
    errors,
    message,
  }
}

/**
 * 在给定规则集与审计报告上评估例外清单。
 *
 * @param rules  当前规则（编辑后调用即自动重算：原子空间随之重建）
 * @param inputs 例外清单原始输入
 * @param now    评估时刻（默认当前时间；测试可注入固定时间）
 */
export function evaluateExceptions(
  rules: RuleInput[],
  inputs: ExceptionInput[],
  now: Date = new Date(),
): ExemptionReport {
  const { valid, invalid: invalidRules } = validateRules(rules)
  const active = valid.filter((r) => r.enabled)

  const invalidRuleIds = new Set(invalidRules.map((r) => r.id))
  const disabledRuleIds = new Set(valid.filter((r) => !r.enabled).map((r) => r.id))

  // 例外 CIDR / 端口边界一并参与原子切分：例外边界即使落在规则原子块内部，
  // 交集也能被精确切开（与策略目标验证相同的做法）。
  const validated: Array<{ input: ExceptionInput; order: number; ex: NormalizedException }> = []
  const prelimInvalid: InvalidException[] = []
  inputs.forEach((input, order) => {
    const { exception, errors } = validateException(input)
    if (!exception) {
      prelimInvalid.push(
        invalidEntry(
          input,
          order,
          normalizeIssueType(input.issueType),
          'invalid',
          errors,
          errors.join('；'),
        ),
      )
      return
    }
    validated.push({ input, order, ex: exception })
  })

  const extraIp = validated.map(({ ex }) => ({ start: ex.ipStart, end: ex.ipEnd }))
  const extraPort = validated.map(({ ex }) => ({
    start: ex.portStart,
    end: ex.portEnd,
  }))
  const ipAtoms = buildIpAtoms(active, extraIp)
  const portAtoms = buildPortAtoms(active, extraPort)
  const owner = buildOwnerMap(active, ipAtoms, portAtoms)

  // 每条活动规则的声明 / 首命中单元
  const runtimes: RuleRuntimeLite[] = active.map((rule, pos) => {
    const declaredKeys = new Set<string>()
    const ownedKeys = new Set<string>()
    const ipIdx = containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)
    const portIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    for (const ip of ipIdx) {
      for (const port of portIdx) {
        for (const proto of PROTO_INDEX.get(rule.protocol)!) {
          const key = `${ip}.${port}.${proto}`
          declaredKeys.add(key)
          if (owner.get(key) === pos) ownedKeys.add(key)
        }
      }
    }
    return {
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      action: rule.action,
      declaredKeys,
      ownedKeys,
    }
  })

  const runtimeByRuleId = new Map(runtimes.map((rt) => [rt.ruleId, rt]))
  const validRuleById = new Map(valid.map((r) => [r.id, r]))

  /** 单元集合的报文空间大小 */
  const sizeOfKeys = (keys: Set<string>): number => {
    let size = 0
    for (const key of keys) {
      const [ip, port] = key.split('.').map(Number)
      size += atomCellSize(ipAtoms[ip], portAtoms[port])
    }
    return size
  }

  /** 字典序最小单元 → 代表报文（确定性、可复现） */
  const packetOf = (keys: Set<string>): ExceptionPacket | null => {
    if (keys.size === 0) return null
    let best: string | null = null
    for (const k of keys) if (best === null || k < best) best = k
    return packetFromKey(best!, ipAtoms, portAtoms)
  }

  // ruleId -> 该规则下各有效例外的覆盖
  const coverageByRule = new Map<
    string,
    Array<{ ex: NormalizedException; coveredKeys: Set<string> }>
  >()
  const invalidEntries: InvalidException[] = [...prelimInvalid]
  const nowMs = now.getTime()

  for (const { input, order, ex } of validated) {
    // 1) 到期判定（先于目标判定：一条过期例外无论目标如何都不豁免）
    if (ex.expiresAtMs !== null && ex.expiresAtMs < nowMs) {
      invalidEntries.push(
        invalidEntry(
          input,
          order,
          ex.issueType,
          'expired',
          [],
          `已于 ${ex.expiresAtText} 到期，不参与豁免`,
        ),
      )
      continue
    }

    // 2) 目标规则状态
    if (invalidRuleIds.has(ex.ruleId)) {
      invalidEntries.push(
        invalidEntry(
          input,
          order,
          ex.issueType,
          'rule-invalid',
          [],
          '目标规则当前为非法规则、不参与分析，例外不生效',
        ),
      )
      continue
    }
    if (disabledRuleIds.has(ex.ruleId)) {
      invalidEntries.push(
        invalidEntry(
          input,
          order,
          ex.issueType,
          'rule-disabled',
          [],
          '目标规则当前已停用、不参与分析，例外不生效',
        ),
      )
      continue
    }
    if (!validRuleById.has(ex.ruleId)) {
      invalidEntries.push(
        invalidEntry(
          input,
          order,
          ex.issueType,
          'rule-missing',
          [],
          '目标规则已不存在（可能已被删除），例外不生效',
        ),
      )
      continue
    }
    const rt = runtimeByRuleId.get(ex.ruleId)!
    const blockedKeys = new Set<string>()
    for (const key of rt.declaredKeys) if (!rt.ownedKeys.has(key)) blockedKeys.add(key)

    let status: RuleIssueStatus
    if (blockedKeys.size === 0) status = 'reachable'
    else if (rt.ownedKeys.size === 0) status = 'fully-shadowed'
    else status = 'partial-shadowed'

    // 3) 问题类型匹配：完全遮蔽例外只作用于完全遮蔽规则，反之亦然
    if (status !== ex.issueType) {
      invalidEntries.push(
        invalidEntry(
          input,
          order,
          ex.issueType,
          'issue-mismatch',
          [],
          `例外声明的问题类型为「${ISSUE_TYPE_TEXT[ex.issueType]}」，但目标规则当前为「${
            status === 'reachable'
              ? '可达（无遮蔽区域）'
              : ISSUE_TYPE_TEXT[status as IssueType]
          }」，例外不生效`,
        ),
      )
      continue
    }

    // 4) 精确交集：例外声明范围 ∩ 规则当前实际遮蔽单元
    const protoIdx = PROTO_INDEX.get(ex.protocol)!
    const coveredKeys = new Set<string>()
    for (const key of blockedKeys) {
      const [ip, port, proto] = key.split('.').map(Number)
      const ipAtom = ipAtoms[ip]
      const portAtom = portAtoms[port]
      if (
        ipAtom.start >= ex.ipStart &&
        ipAtom.end <= ex.ipEnd &&
        portAtom.start >= ex.portStart &&
        portAtom.end <= ex.portEnd &&
        protoIdx.includes(proto)
      ) {
        coveredKeys.add(key)
      }
    }
    let list = coverageByRule.get(ex.ruleId)
    if (!list) {
      list = []
      coverageByRule.set(ex.ruleId, list)
    }
    list.push({ ex, coveredKeys })
  }

  // 组装每条「有遮蔽区域」规则的豁免分解（即使没有任何例外，也列出待处理区域）
  const ruleEntries: RuleExemption[] = []
  for (const rt of runtimes) {
    const blockedKeys = new Set<string>()
    for (const key of rt.declaredKeys) if (!rt.ownedKeys.has(key)) blockedKeys.add(key)
    if (blockedKeys.size === 0) continue

    const status: RuleIssueStatus =
      rt.ownedKeys.size === 0 ? 'fully-shadowed' : 'partial-shadowed'
    const rule = validRuleById.get(rt.ruleId)!
    const declaredSize =
      (rule.ipEnd - rule.ipStart + 1) *
      (rule.portEnd - rule.portStart + 1) *
      PROTO_INDEX.get(rule.protocol)!.length
    const blockedSize = sizeOfKeys(blockedKeys)

    const covList = coverageByRule.get(rt.ruleId) ?? []
    const exemptUnion = new Set<string>()
    const coverages: ExceptionCoverage[] = covList.map(({ ex, coveredKeys }) => {
      for (const k of coveredKeys) exemptUnion.add(k)
      const coveredSize = sizeOfKeys(coveredKeys)
      return {
        exceptionId: ex.id,
        issueType: ex.issueType,
        cidrText: ex.cidrText,
        portStart: ex.portStart,
        portEnd: ex.portEnd,
        protocol: ex.protocol,
        expiresAtMs: ex.expiresAtMs,
        expiresAtText: ex.expiresAtText,
        notes: ex.notes,
        coveredSize,
        coveredCells: coveredKeys.size,
        regions: buildExactRegions(coveredKeys, ipAtoms, portAtoms),
        representative: packetOf(coveredKeys),
        noOverlap: coveredKeys.size === 0,
      }
    })
    coverages.sort(
      (a, b) =>
        b.coveredSize - a.coveredSize ||
        (a.exceptionId < b.exceptionId ? -1 : a.exceptionId > b.exceptionId ? 1 : 0),
    )

    const pendingKeys = new Set<string>()
    for (const key of blockedKeys) if (!exemptUnion.has(key)) pendingKeys.add(key)

    const exemptSize = sizeOfKeys(exemptUnion)
    const pendingSize = sizeOfKeys(pendingKeys)

    ruleEntries.push({
      kind: 'rule',
      ruleId: rt.ruleId,
      ruleIndex: rt.ruleIndex,
      ruleName: rt.ruleName,
      action: rt.action,
      ruleStatus: status,
      declaredSize,
      blockedSize,
      blockedCells: blockedKeys.size,
      exemptSize,
      exemptCells: exemptUnion.size,
      pendingSize,
      pendingCells: pendingKeys.size,
      exemptRatio: blockedSize === 0 ? 0 : exemptSize / blockedSize,
      fullyExempt: pendingKeys.size === 0,
      coverages,
      exemptRegions: buildExactRegions(exemptUnion, ipAtoms, portAtoms),
      exemptRepresentative: packetOf(exemptUnion),
      pendingRegions: buildExactRegions(pendingKeys, ipAtoms, portAtoms),
      pendingRepresentative: packetOf(pendingKeys),
    })
  }

  ruleEntries.sort((a, b) => a.ruleIndex - b.ruleIndex)

  // 不参与豁免的例外按清单原始顺序展示（ruleEntries 按规则序号在前），
  // 使非法 / 过期提示与用户在清单中看到的条目位置一一对应。
  invalidEntries.sort((a, b) => a.order - b.order)

  const entries: ExemptionEntry[] = [...ruleEntries, ...invalidEntries]

  const countReason = (reason: InvalidExceptionReason) =>
    invalidEntries.filter((e) => e.reason === reason).length
  const invalidCount = countReason('invalid')
  const expiredCount = countReason('expired')
  const targetBadCount =
    countReason('rule-missing') + countReason('rule-invalid') + countReason('rule-disabled')
  const mismatchCount = countReason('issue-mismatch')
  const activeCount = validated.length - expiredCount - targetBadCount - mismatchCount
  const noOverlapCount = ruleEntries.reduce(
    (sum, re) => sum + re.coverages.filter((c) => c.noOverlap).length,
    0,
  )
  const totalBlockedSize = ruleEntries.reduce((s, e) => s + e.blockedSize, 0)
  const totalExemptSize = ruleEntries.reduce((s, e) => s + e.exemptSize, 0)
  const totalPendingSize = ruleEntries.reduce((s, e) => s + e.pendingSize, 0)

  return {
    generatedAt: now.toISOString(),
    evaluatedAt: now.toISOString(),
    entries,
    stats: {
      totalExceptions: inputs.length,
      invalidCount,
      expiredCount,
      targetBadCount,
      mismatchCount,
      activeCount,
      noOverlapCount,
      issueRuleCount: ruleEntries.length,
      fullyExemptRuleCount: ruleEntries.filter((e) => e.fullyExempt).length,
      partiallyExemptRuleCount: ruleEntries.filter(
        (e) => !e.fullyExempt && e.exemptSize > 0,
      ).length,
      totalBlockedSize,
      totalExemptSize,
      totalPendingSize,
    },
  }
}

/** 在审计报告中按规则 id 取豁免分解（UI 结果区使用） */
export function findRuleExemption(
  report: ExemptionReport,
  ruleId: string,
): RuleExemption | undefined {
  return report.entries.find(
    (e): e is RuleExemption => e.kind === 'rule' && e.ruleId === ruleId,
  )
}

// ---------------------------------------------------------------------------
// 导入 / 导出
// ---------------------------------------------------------------------------

export interface ExceptionsFile {
  format: 'audit-exceptions'
  version: 1
  exportedAt: string
  exceptions: ExceptionInput[]
}

export function serializeExceptions(
  inputs: ExceptionInput[],
  now: Date = new Date(),
): string {
  const file: ExceptionsFile = {
    format: 'audit-exceptions',
    version: 1,
    exportedAt: now.toISOString(),
    exceptions: inputs,
  }
  return JSON.stringify(file, null, 2)
}

export interface ParseExceptionsResult {
  exceptions: ExceptionInput[]
  errors: string[]
}

/**
 * 解析例外清单 JSON。支持：
 *   { format: 'audit-exceptions', exceptions: [...] }
 *   { exceptions: [...] }
 *   [ ... ]
 * 非法 JSON / 结构错误整体返回 error；逐字段的合法性问题不在导入时拦截
 * （与规则导入一致：条目保留在清单中，由评估标记为非法、不参与豁免）。
 * 同一文件内 id 重复会给出提示并为后者重新生成 id。
 */
export function parseExceptionsJson(text: string): ParseExceptionsResult {
  const errors: string[] = []
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    return { exceptions: [], errors: [`JSON 解析失败：${(err as Error).message}`] }
  }

  let arr: unknown
  if (Array.isArray(data)) {
    arr = data
  } else if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    if (Array.isArray(obj.exceptions)) {
      arr = obj.exceptions
      if (typeof obj.format === 'string' && obj.format !== 'audit-exceptions') {
        errors.push(`文件 format 为 “${obj.format}”，仍按例外清单格式尝试解析`)
      }
    } else {
      return { exceptions: [], errors: ['根对象必须含 exceptions 数组字段'] }
    }
  } else {
    return { exceptions: [], errors: ['根节点必须是数组或含 exceptions 字段的对象'] }
  }

  const seen = new Set<string>()
  const exceptions: ExceptionInput[] = []
  ;(arr as unknown[]).forEach((item, i) => {
    if (!item || typeof item !== 'object') {
      errors.push(`第 ${i + 1} 条：不是对象，已跳过`)
      return
    }
    const o = item as Record<string, unknown>
    const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v))
    const pickPort = (v: unknown): string | number =>
      typeof v === 'number' ? v : str(v)
    let id = typeof o.id === 'string' ? o.id : makeId()
    if (!id) id = makeId()
    if (seen.has(id)) {
      errors.push(`第 ${i + 1} 条：id ${id} 在文件内重复，已为其重新分配 id`)
      id = makeId()
    }
    seen.add(id)
    exceptions.push({
      id,
      ruleId: str(o.ruleId ?? o.ruleID),
      issueType: str(o.issueType ?? o.issue),
      cidr: str(o.cidr),
      portStart: pickPort(o.portStart),
      portEnd: pickPort(o.portEnd),
      protocol: str(o.protocol).toUpperCase(),
      expiresAt: str(o.expiresAt ?? o.expires ?? o.expiry),
      notes: str(o.notes ?? o.note ?? o.reason ?? o.description),
    })
  })

  return { exceptions, errors }
}
