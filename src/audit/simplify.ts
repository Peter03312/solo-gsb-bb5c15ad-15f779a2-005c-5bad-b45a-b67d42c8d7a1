/**
 * 无损精简（lossless simplification）。
 *
 * 对每条「已启用、合法且当前有有效流量」的规则，独立地模拟一次单独删除
 * （各候选互不影响，均从原始规则集出发删除一条），并在与现有首命中审计
 * 完全相同的一套 IPv4 原子块 × 端口原子段 × 协议离散单元空间中，逐单元
 * 比较删除前后的最终动作：
 *
 *   - 删除前该单元首命中规则 R（即 R 的有效流量）；
 *   - 删除 R 后，该单元的首命中者是其后第一条仍覆盖它的规则；
 *     R 之前的规则不可能覆盖 R 的有效单元（否则该单元原本就不会归 R）；
 *   - 若其后没有任何规则覆盖，则该单元变为「未命中任何规则」——
 *     未命中被当作一种独立的比较结果，而不是按覆盖率推断。
 *
 * 只有 R 的全部有效单元在删除后仍得到**相同动作**（每个单元都被某条
 * 后续规则以与 R 相同的动作接管）时，R 才被列为「可安全删除」。
 *
 * 每条建议给出其原有效流量被哪些后续规则接管的**精确区域**
 * （协议 → 连续端口段 × 规范 CIDR 的行式展开，非矩形区域不做笛卡尔积
 * 近似）、接管动作与确定性、可复制的代表报文；不安全的候选同样列出
 * 动作会改变（含变为未命中）的冲突区域，供判断不能删除的原因。
 */
import {
  activeRules,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  decodeCellKey,
  firstKey,
  packetFromKey,
  PROTO_INDEX,
  validateRules,
} from './engine'
import type {
  ExactRegionGroup,
  Protocol,
  RuleInput,
} from './types'

export interface SimplifyPacket {
  srcIp: string
  srcPort: number
  protocol: Extract<Protocol, 'TCP' | 'UDP'>
}

/** 一组删除后去向相同的原有效流量（同一接管规则 / 未命中） */
interface CellBucket {
  keys: Set<string>
  size: number
  cells: number
  regions: ExactRegionGroup[]
  packet: SimplifyPacket
}

/** 安全删除时的接管分组：后续规则以相同动作接管的精确区域 */
export interface TakeoverGroup {
  ruleId: string
  ruleIndex: number
  ruleName: string
  /** 接管动作，与被删规则动作一致 */
  action: string
  size: number
  cells: number
  regions: ExactRegionGroup[]
  packet: SimplifyPacket
}

/** 不安全删除时的冲突分组 */
export interface TakeoverConflict {
  /** action-changed = 被后续规则以不同动作接管；unmatched = 删除后未命中任何规则 */
  kind: 'action-changed' | 'unmatched'
  /** 接管规则（unmatched 时为 null） */
  ruleId: string | null
  ruleIndex: number | null
  ruleName: string | null
  /** 删除后该区域的最终动作；未命中时为 null */
  afterAction: string | null
  size: number
  cells: number
  regions: ExactRegionGroup[]
  packet: SimplifyPacket
}

export interface SimplifyCandidate {
  kind: 'candidate'
  ruleId: string
  ruleIndex: number
  ruleName: string
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  action: string
  /** 该规则当前的有效（首命中）流量大小与单元数 */
  effectiveSize: number
  effectiveCells: number
  /** 删除后所有报文最终动作是否保持不变 */
  safe: boolean
  /** 安全候选：按后续接管规则分组的精确区域（区域两两互斥，合计 = 有效流量） */
  takeovers: TakeoverGroup[]
  /** 不安全候选：动作会变化（含变为未命中）的冲突分组 */
  conflicts: TakeoverConflict[]
}

/** 未参与逐条模拟的规则（停用 / 非法 / 无有效流量） */
export interface SimplifySkipped {
  kind: 'skipped'
  ruleId: string
  ruleIndex: number
  ruleName: string
  reason: 'disabled' | 'invalid' | 'no-traffic'
}

export interface SimplifyResult {
  generatedAt: string
  items: Array<SimplifyCandidate | SimplifySkipped>
  /** 参与逐条模拟（启用、合法、有有效流量）的规则数 */
  analyzedCount: number
  safeCount: number
  unsafeCount: number
  /** 启用且合法但有效流量为 0（完全遮蔽 / 空区域）的规则数 */
  skippedNoTraffic: number
  skippedDisabled: number
  skippedInvalid: number
}

function makeBucket(
  keys: Set<string>,
  ipAtoms: ReturnType<typeof buildIpAtoms>,
  portAtoms: ReturnType<typeof buildPortAtoms>,
): CellBucket {
  let size = 0
  for (const key of keys) {
    const { ip, port } = decodeCellKey(key)
    size += atomCellSize(ipAtoms[ip], portAtoms[port])
  }
  const sample = firstKey(keys)
  return {
    keys,
    size,
    cells: keys.size,
    regions: buildExactRegions(keys, ipAtoms, portAtoms),
    packet: packetFromKey(sample, ipAtoms, portAtoms) as SimplifyPacket,
  }
}

/**
 * 执行无损精简分析：逐条模拟删除并比较删除前后每个单元的最终动作。
 * 纯函数，不修改传入规则。
 */
export function analyzeSimplify(
  inputs: RuleInput[],
  now: Date = new Date(),
): SimplifyResult {
  const { valid, invalid } = validateRules(inputs)
  const active = activeRules(inputs)
  const disabledCount = valid.length - active.length

  // 与审计共享同一套原子空间：删除模拟不重新切分（规则集合是其子集），
  // 单元 key 在删除前后完全对齐，可逐单元比较最终动作。
  const ipAtoms = buildIpAtoms(active)
  const portAtoms = buildPortAtoms(active)
  const owner = buildOwnerMap(active, ipAtoms, portAtoms)

  // 每条启用规则声明的单元集合（用于删除后判断某单元被谁接管）
  const declaredSets = active.map((rule) => {
    const set = new Set<string>()
    const ipIdx = containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)
    const portIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    for (const ip of ipIdx) {
      for (const port of portIdx) {
        for (const proto of PROTO_INDEX.get(rule.protocol)!) {
          set.add(`${ip}.${port}.${proto}`)
        }
      }
    }
    return set
  })

  // pos -> 归属于该规则（首命中）的单元 key
  const ownedBy = new Map<number, Set<string>>()
  for (const [key, pos] of owner) {
    let set = ownedBy.get(pos)
    if (!set) {
      set = new Set()
      ownedBy.set(pos, set)
    }
    set.add(key)
  }

  const items: Array<SimplifyCandidate | SimplifySkipped> = []
  let analyzedCount = 0
  let safeCount = 0
  let skippedNoTraffic = 0

  active.forEach((rule, pos) => {
    const ownedKeys = ownedBy.get(pos)
    if (!ownedKeys || ownedKeys.size === 0) {
      skippedNoTraffic++
      items.push({
        kind: 'skipped',
        ruleId: rule.id,
        ruleIndex: rule.index,
        ruleName: rule.name,
        reason: 'no-traffic',
      })
      return
    }
    analyzedCount++

    // 删除后的去向分桶：
    //   takeover:<q>  → 被后续规则 q 接管；unmatched → 未命中任何规则
    const buckets = new Map<string, Set<string>>()
    const bucketKeys = (tag: string): Set<string> => {
      let set = buckets.get(tag)
      if (!set) {
        set = new Set()
        buckets.set(tag, set)
      }
      return set
    }

    for (const key of ownedKeys) {
      // 只有位于 R 之后的规则可能接管：更靠前的规则若覆盖该单元，
      // 该单元原本就不会以 R 为首命中者。
      let takeover = -1
      for (let q = pos + 1; q < active.length; q++) {
        if (declaredSets[q].has(key)) {
          takeover = q
          break
        }
      }
      if (takeover === -1) bucketKeys('unmatched').add(key)
      else bucketKeys(`take:${takeover}`).add(key)
    }

    const takeovers: TakeoverGroup[] = []
    const conflicts: TakeoverConflict[] = []
    let safe = true

    for (const [tag, keys] of buckets) {
      const bucket = makeBucket(keys, ipAtoms, portAtoms)
      if (tag === 'unmatched') {
        safe = false
        conflicts.push({
          kind: 'unmatched',
          ruleId: null,
          ruleIndex: null,
          ruleName: null,
          afterAction: null,
          size: bucket.size,
          cells: bucket.cells,
          regions: bucket.regions,
          packet: bucket.packet,
        })
        continue
      }
      const q = Number(tag.slice('take:'.length))
      const successor = active[q]
      if (successor.action === rule.action) {
        takeovers.push({
          ruleId: successor.id,
          ruleIndex: successor.index,
          ruleName: successor.name,
          action: successor.action,
          size: bucket.size,
          cells: bucket.cells,
          regions: bucket.regions,
          packet: bucket.packet,
        })
      } else {
        safe = false
        conflicts.push({
          kind: 'action-changed',
          ruleId: successor.id,
          ruleIndex: successor.index,
          ruleName: successor.name,
          afterAction: successor.action,
          size: bucket.size,
          cells: bucket.cells,
          regions: bucket.regions,
          packet: bucket.packet,
        })
      }
    }

    // 展示顺序：接管 / 冲突均按空间大小降序、同大小按规则序号，保证确定性
    takeovers.sort((a, b) => b.size - a.size || a.ruleIndex - b.ruleIndex)
    conflicts.sort((a, b) => {
      const ai = a.ruleIndex ?? Number.MAX_SAFE_INTEGER
      const bi = b.ruleIndex ?? Number.MAX_SAFE_INTEGER
      return b.size - a.size || ai - bi
    })
    if (safe) safeCount++

    let effectiveSize = 0
    for (const key of ownedKeys) {
      const { ip, port } = decodeCellKey(key)
      effectiveSize += atomCellSize(ipAtoms[ip], portAtoms[port])
    }

    items.push({
      kind: 'candidate',
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      cidrText: rule.cidrText,
      portStart: rule.portStart,
      portEnd: rule.portEnd,
      protocol: rule.protocol,
      action: rule.action,
      effectiveSize,
      effectiveCells: ownedKeys.size,
      safe,
      takeovers,
      conflicts,
    })
  })

  // 停用与非法规则也列入跳过清单（默认不在面板展开，仅用于计数与说明）
  for (const rule of valid) {
    if (rule.enabled) continue
    items.push({
      kind: 'skipped',
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      reason: 'disabled',
    })
  }
  for (const bad of invalid) {
    items.push({
      kind: 'skipped',
      ruleId: bad.id,
      ruleIndex: bad.index,
      ruleName: bad.name,
      reason: 'invalid',
    })
  }

  items.sort((a, b) => a.ruleIndex - b.ruleIndex)

  return {
    generatedAt: now.toISOString(),
    items,
    analyzedCount,
    safeCount,
    unsafeCount: analyzedCount - safeCount,
    skippedNoTraffic,
    skippedDisabled: disabledCount,
    skippedInvalid: invalid.length,
  }
}
