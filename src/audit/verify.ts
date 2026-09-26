/**
 * 策略目标验证（只读）。
 *
 * 给定一个验证目标（IPv4 CIDR × 端口区间 × 协议 × 期望动作），在
 * 「自上而下、首条命中」语义下对当前规则执行一次只读检查，不改动任何规则。
 * 目标 CIDR / 端口边界会追加进原子切分，因此目标边界即使落在既有原子块
 * 内部也能被精确切开；随后目标报文空间中的每个原子单元按实际首命中结果
 * 分为三类：
 *
 *   1. 符合期望      —— 首命中规则的动作 === 期望动作
 *   2. 命中其他动作  —— 首命中规则存在但动作不同，按实际动作分组汇总
 *   3. 未命中任何规则 —— 没有任何合法规则覆盖该单元
 *
 * 非法规则与审计一致地被排除（不参与首命中计算）；协议 ANY 分别按 TCP、UDP
 * 两个具体协议检查。违规区域按「协议 → 连续端口段 → 规范 CIDR 列表」精确
 * 展开（不是 IP 集合 × 端口集合的笛卡尔积近似），每类违规给出确定性的
 * 可复制代表报文。
 */
import {
  activeRules,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  concreteProtocolOf,
  containedIndices,
  exampleIp,
  protocolDimIndices,
  validatePortRange,
  validateRules,
} from './engine'
import { intToIpv4, parseCidrStrict } from './iputil'
import type { ExactRegionGroup, ExactRegionRow, Protocol, RuleInput } from './types'

type ConcreteProtocol = Exclude<Protocol, 'ANY'>

/** 面板输入的验证目标（原始形态，端口允许字符串） */
export interface GoalInput {
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  expectedAction: string
}

/** 校验通过后的规范目标 */
export interface NormalizedGoal {
  ipStart: number
  ipEnd: number
  prefix: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  expectedAction: string
}

/** 可复制的代表报文 */
export interface GoalPacket {
  srcIp: string
  srcPort: number
  protocol: ConcreteProtocol
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR（与引擎共享同一套类型与构建） */
export type GoalRegionRow = ExactRegionRow
export type GoalRegionGroup = ExactRegionGroup

/** 命中其他动作的违规分组（按实际动作汇总） */
export interface GoalActionGroup {
  action: string
  size: number
  ratio: number
  cells: number
  regions: GoalRegionGroup[]
  /** 每个具体协议一个确定性代表报文（ANY 目标时最多 TCP / UDP 各一） */
  examples: Array<
    GoalPacket & { matchedRuleIndex: number; matchedRuleName: string }
  >
}

/** 未命中任何规则的违规分类 */
export interface GoalUnmatched {
  size: number
  ratio: number
  cells: number
  regions: GoalRegionGroup[]
  examples: GoalPacket[]
}

export interface GoalProtocolBreakdown {
  protocol: ConcreteProtocol
  conformSize: number
  otherActionSize: number
  unmatchedSize: number
}

export interface GoalVerifyResult {
  goal: NormalizedGoal
  /** 目标报文空间总大小（ANY 目标为 TCP / UDP 两协议合计） */
  totalSize: number
  conformSize: number
  conformRatio: number
  otherActionSize: number
  otherActionRatio: number
  unmatchedSize: number
  unmatchedRatio: number
  /** 按实际动作汇总的违规分组（按空间大小降序，同大小按动作名排序） */
  actionGroups: GoalActionGroup[]
  unmatched: GoalUnmatched | null
  /** 按 TCP / UDP 分别统计（ANY 目标时两协议各自独立检查） */
  perProtocol: GoalProtocolBreakdown[]
  /** 参与验证的合法且启用的规则数 */
  validRuleCount: number
  /** 被排除的非法规则数 */
  invalidExcluded: number
  /** 被排除的停用规则数（合法但 enabled=false） */
  disabledExcluded: number
}

export type GoalVerifyOutcome =
  | { ok: true; result: GoalVerifyResult }
  | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// 目标校验（与规则同一套严格标准）
// ---------------------------------------------------------------------------

export function validateGoal(input: GoalInput): {
  goal: NormalizedGoal | null
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

  const expectedAction = input.expectedAction.trim()
  if (!expectedAction) errors.push('期望动作不能为空')

  if (errors.length > 0 || !cidr || protocol === null) {
    return { goal: null, errors }
  }
  return {
    goal: {
      ipStart: cidr.start,
      ipEnd: cidr.end,
      prefix: cidr.prefix,
      cidrText: cidr.canonical,
      portStart: ports.portStart,
      portEnd: ports.portEnd,
      protocol,
      expectedAction,
    },
    errors: [],
  }
}

// ---------------------------------------------------------------------------
// 主验证流程
// ---------------------------------------------------------------------------

export function verifyGoal(rules: RuleInput[], input: GoalInput): GoalVerifyOutcome {
  const { goal, errors } = validateGoal(input)
  if (!goal) return { ok: false, errors }

  // 非法规则与停用规则均按既有语义排除，不参与首命中计算
  const { valid, invalid } = validateRules(rules)
  const active = activeRules(rules)
  const disabledCount = valid.length - active.length

  // 目标边界追加进原子切分：即使落在规则原子块内部也被精确切开
  const ipAtoms = buildIpAtoms(active, [{ start: goal.ipStart, end: goal.ipEnd }])
  const portAtoms = buildPortAtoms(active, [
    { start: goal.portStart, end: goal.portEnd },
  ])
  const owner = buildOwnerMap(active, ipAtoms, portAtoms)

  const ipIdx = containedIndices(ipAtoms, goal.ipStart, goal.ipEnd)
  const portIdx = containedIndices(portAtoms, goal.portStart, goal.portEnd)
  const protoIdx = protocolDimIndices(goal.protocol)

  const unmatchedKeys = new Set<string>()
  const otherKeys = new Map<string, Set<string>>() // 实际动作 -> 单元
  // 每个（分组, 协议）记录扫描序首个单元，作为确定性的代表报文来源
  const firstKey = new Map<string, string>()

  let conformSize = 0
  let otherSize = 0
  let unmatchedSize = 0
  const perProto = [
    { conform: 0, other: 0, unmatched: 0 },
    { conform: 0, other: 0, unmatched: 0 },
  ]

  for (const ip of ipIdx) {
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`
        const pos = owner.get(key)
        let groupKey: string
        if (pos === undefined) {
          unmatchedKeys.add(key)
          unmatchedSize += size
          perProto[proto].unmatched += size
          groupKey = '#unmatched'
        } else {
          const action = active[pos].action
          if (action === goal.expectedAction) {
            conformSize += size
            perProto[proto].conform += size
            groupKey = '#conform'
          } else {
            let set = otherKeys.get(action)
            if (!set) {
              set = new Set()
              otherKeys.set(action, set)
            }
            set.add(key)
            otherSize += size
            perProto[proto].other += size
            groupKey = `action:${action}`
          }
        }
        const fk = `${groupKey}|${proto}`
        if (!firstKey.has(fk)) firstKey.set(fk, key)
      }
    }
  }

  const totalSize = conformSize + otherSize + unmatchedSize
  const ratio = (n: number) => (totalSize === 0 ? 0 : n / totalSize)

  const packetOf = (key: string): GoalPacket => {
    const [ip, port, proto] = key.split('.').map(Number)
    return {
      srcIp: intToIpv4(exampleIp(ipAtoms[ip])),
      srcPort: portAtoms[port].start,
      protocol: concreteProtocolOf(proto),
    }
  }

  const actionGroups: GoalActionGroup[] = [...otherKeys.entries()]
    .map(([action, keys]) => {
      let size = 0
      for (const key of keys) {
        const [ip, port] = key.split('.').map(Number)
        size += atomCellSize(ipAtoms[ip], portAtoms[port])
      }
      const examples: GoalActionGroup['examples'] = []
      for (const proto of [0, 1]) {
        const key = firstKey.get(`action:${action}|${proto}`)
        if (!key) continue
        const pos = owner.get(key)!
        examples.push({
          ...packetOf(key),
          matchedRuleIndex: active[pos].index,
          matchedRuleName: active[pos].name,
        })
      }
      return {
        action,
        size,
        ratio: ratio(size),
        cells: keys.size,
        regions: buildExactRegions(keys, ipAtoms, portAtoms),
        examples,
      }
    })
    .sort(
      (a, b) =>
        b.size - a.size || (a.action < b.action ? -1 : a.action > b.action ? 1 : 0),
    )

  const unmatched: GoalUnmatched | null =
    unmatchedKeys.size === 0
      ? null
      : {
          size: unmatchedSize,
          ratio: ratio(unmatchedSize),
          cells: unmatchedKeys.size,
          regions: buildExactRegions(unmatchedKeys, ipAtoms, portAtoms),
          examples: [0, 1]
            .map((proto) => firstKey.get(`#unmatched|${proto}`))
            .filter((k): k is string => k !== undefined)
            .map(packetOf),
        }

  return {
    ok: true,
    result: {
      goal,
      totalSize,
      conformSize,
      conformRatio: ratio(conformSize),
      otherActionSize: otherSize,
      otherActionRatio: ratio(otherSize),
      unmatchedSize,
      unmatchedRatio: ratio(unmatchedSize),
      actionGroups,
      unmatched,
      perProtocol: [0, 1].map((proto) => ({
        protocol: concreteProtocolOf(proto),
        conformSize: perProto[proto].conform,
        otherActionSize: perProto[proto].other,
        unmatchedSize: perProto[proto].unmatched,
      })),
      validRuleCount: active.length,
      invalidExcluded: invalid.length,
      disabledExcluded: disabledCount,
    },
  }
}
