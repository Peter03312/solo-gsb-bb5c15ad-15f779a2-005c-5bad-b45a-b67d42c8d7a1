/**
 * 策略回归样例生成器。
 *
 * 在与首命中审计完全相同的一套 IPv4 原子块 × 端口原子段 × 协议离散单元空间中
 * （仅纳入合法且已启用的规则；非法 / 停用规则按既有语义排除），为当前规则集
 * 生成一组**紧凑的回归测试报文**，覆盖目标分两类：
 *
 *   1. 首命中目标：每条**实际可达**（拥有首命中单元）的规则，至少被一个样例
 *      报文首命中一次；
 *   2. 阻挡见证目标：每一组「首命中规则 b 阻挡后续规则 s」的关系（即存在某个
 *      单元首命中 b、且 s 也声明了它），至少被一个样例报文见证一次——
 *      该报文看似属于 s，实际首命中 b。
 *
 * 一个候选报文（一个原子单元）可以同时覆盖多个目标：它首命中的规则的
 * 首命中目标，以及它作为见证的全部阻挡关系。样例集合按确定性贪心生成：
 * 每轮选取「覆盖尚未覆盖目标数最多」的候选报文，并列时按
 * 协议（TCP < UDP）/ IP / 端口升序取最小者，直到全部目标被覆盖。
 * 由于每个目标按构造都至少有一个见证单元，贪心必然全覆盖；
 * 同一规则集多次生成的结果完全一致（确定、可复现）。
 */
import {
  activeRules,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  packetFromKey,
  PROTO_INDEX,
} from './engine'
import { ipv4ToInt } from './iputil'
import type { Protocol, RuleInput } from './types'

/** 可复制的回归样例报文 */
export interface RegressionPacket {
  srcIp: string
  srcPort: number
  protocol: Extract<Protocol, 'TCP' | 'UDP'>
}

/** 一个覆盖目标：某条规则的首命中，或一组「首命中规则阻挡后续规则」的关系 */
export interface RegressionGoal {
  id: string
  kind: 'first-hit' | 'block'
  /** 实施首命中（即阻挡方）的规则 */
  hitterRuleId: string
  hitterRuleIndex: number
  hitterRuleName: string
  /** 仅 block 目标：被阻挡的后续规则 */
  blockedRuleId: string | null
  blockedRuleIndex: number | null
  blockedRuleName: string | null
  /** 人类可读描述（导出 JSON 与面板展示共用） */
  description: string
  /** 覆盖该目标的样例序号（samples 下标，从 0 计）；-1 = 未被覆盖 */
  coveredBy: number
}

/** 一条回归样例：报文 + 预期首命中规则 / 动作 + 它覆盖的目标 */
export interface RegressionSample {
  packet: RegressionPacket
  matchedRuleId: string
  matchedRuleIndex: number
  matchedRuleName: string
  action: string
  /** 该样例覆盖的目标 id（按目标定义顺序排列） */
  coveredGoalIds: string[]
}

export interface RegressionResult {
  generatedAt: string
  /** 合法且启用的规则数（参与生成的规则） */
  activeRuleCount: number
  /** 实际可达（拥有首命中单元）的规则数 */
  reachableRuleCount: number
  goalCount: number
  firstHitGoalCount: number
  blockGoalCount: number
  coveredGoalCount: number
  goals: RegressionGoal[]
  samples: RegressionSample[]
}

/** 协议升序：TCP 在 UDP 之前（与协议维下标一致） */
function protocolOrder(p: RegressionPacket['protocol']): number {
  return p === 'TCP' ? 0 : 1
}

/**
 * 生成策略回归样例集。纯函数，不修改传入规则；
 * 同一规则集多次调用结果完全一致。
 */
export function generateRegressionSamples(
  inputs: RuleInput[],
  now: Date = new Date(),
): RegressionResult {
  const active = activeRules(inputs)

  // 与审计共享同一套原子空间：单元 key 与首命中归属完全对齐
  const ipAtoms = buildIpAtoms(active)
  const portAtoms = buildPortAtoms(active)
  const owner = buildOwnerMap(active, ipAtoms, portAtoms)

  // 每条启用规则声明的单元集合（用于判定「后续规则也声明了该单元」的阻挡关系）
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

  // ---- 收集覆盖目标 ----
  // 首命中目标：按规则顺序，仅实际可达（拥有首命中单元）的规则
  const ownedCount = new Map<number, number>()
  for (const pos of owner.values()) {
    ownedCount.set(pos, (ownedCount.get(pos) ?? 0) + 1)
  }

  interface GoalDef {
    id: string
    kind: 'first-hit' | 'block'
    hitter: number
    blocked: number | null
  }
  const goalDefs: GoalDef[] = []
  for (let pos = 0; pos < active.length; pos++) {
    if ((ownedCount.get(pos) ?? 0) > 0) {
      goalDefs.push({ id: `hit:${active[pos].id}`, kind: 'first-hit', hitter: pos, blocked: null })
    }
  }
  // 阻挡见证目标：单元首命中 b 且被后续规则 s 声明 → 关系 (b, s)；按 (b, s) 升序收集
  const blockPairs = new Set<number>() // b * active.length + s
  // 单元 → 它覆盖的目标 id（首命中目标 + 全部阻挡见证目标）
  const cellGoals = new Map<string, string[]>()
  for (const [key, b] of owner) {
    const goals: string[] = [`hit:${active[b].id}`]
    for (let s = b + 1; s < active.length; s++) {
      if (declaredSets[s].has(key)) {
        goals.push(`block:${active[b].id}:${active[s].id}`)
        blockPairs.add(b * active.length + s)
      }
    }
    cellGoals.set(key, goals)
  }
  for (const pair of [...blockPairs].sort((x, y) => x - y)) {
    const b = Math.floor(pair / active.length)
    const s = pair % active.length
    goalDefs.push({ id: `block:${active[b].id}:${active[s].id}`, kind: 'block', hitter: b, blocked: s })
  }

  // ---- 确定性贪心集合覆盖 ----
  // 候选单元按（协议 / IP / 端口）升序排列：遍历时首个达到最大覆盖数者即为
  // 平局中的最小者，与「未覆盖目标数最多优先、再按协议/IP/端口升序」一致。
  const candidates = [...owner.keys()].map((key) => ({
    key,
    packet: packetFromKey(key, ipAtoms, portAtoms),
  }))
  candidates.sort(
    (a, b) =>
      protocolOrder(a.packet.protocol) - protocolOrder(b.packet.protocol) ||
      ipv4ToInt(a.packet.srcIp) - ipv4ToInt(b.packet.srcIp) ||
      a.packet.srcPort - b.packet.srcPort,
  )

  // 目标 → 覆盖它的全部单元（用于选中样例后递减各候选的未覆盖计数）
  const goalCells = new Map<string, string[]>()
  for (const [key, goals] of cellGoals) {
    for (const g of goals) {
      const list = goalCells.get(g)
      if (list) list.push(key)
      else goalCells.set(g, [key])
    }
  }

  const uncovered = new Set(goalDefs.map((g) => g.id))
  const remaining = new Map<string, number>() // 单元 key -> 尚未覆盖的目标数
  for (const [key, goals] of cellGoals) remaining.set(key, goals.length)

  const samples: RegressionSample[] = []
  const coveredBy = new Map<string, number>()

  while (uncovered.size > 0) {
    let best: (typeof candidates)[number] | null = null
    let bestCount = 0
    for (const cand of candidates) {
      const count = remaining.get(cand.key) ?? 0
      if (count > bestCount) {
        bestCount = count
        best = cand
      }
    }
    // 每个目标按构造都有见证单元，不会走到这里；防御性退出避免死循环
    if (!best || bestCount === 0) break

    const sampleIndex = samples.length
    const coveredNow: string[] = []
    for (const g of cellGoals.get(best.key)!) {
      if (!uncovered.has(g)) continue
      uncovered.delete(g)
      coveredNow.push(g)
      coveredBy.set(g, sampleIndex)
      for (const other of goalCells.get(g)!) {
        if (other === best.key) continue
        remaining.set(other, (remaining.get(other) ?? 0) - 1)
      }
    }
    // 已选单元的全部目标至此均已覆盖，置零避免被重复选中
    remaining.set(best.key, 0)

    const hitter = active[owner.get(best.key)!]
    samples.push({
      packet: best.packet,
      matchedRuleId: hitter.id,
      matchedRuleIndex: hitter.index,
      matchedRuleName: hitter.name,
      action: hitter.action,
      coveredGoalIds: coveredNow,
    })
  }

  // ---- 汇总目标表（coveredGoalIds 按目标定义顺序排列） ----
  const goalOrder = new Map(goalDefs.map((g, i) => [g.id, i]))
  for (const sample of samples) {
    sample.coveredGoalIds.sort((a, b) => goalOrder.get(a)! - goalOrder.get(b)!)
  }

  const goals: RegressionGoal[] = goalDefs.map((def) => {
    const hitter = active[def.hitter]
    const blocked = def.blocked === null ? null : active[def.blocked]
    return {
      id: def.id,
      kind: def.kind,
      hitterRuleId: hitter.id,
      hitterRuleIndex: hitter.index,
      hitterRuleName: hitter.name,
      blockedRuleId: blocked?.id ?? null,
      blockedRuleIndex: blocked?.index ?? null,
      blockedRuleName: blocked?.name ?? null,
      description:
        def.kind === 'first-hit'
          ? `首命中 #${hitter.index + 1} ${hitter.name}`
          : `阻挡见证 #${hitter.index + 1} ${hitter.name} 阻挡 #${blocked!.index + 1} ${blocked!.name}`,
      coveredBy: coveredBy.get(def.id) ?? -1,
    }
  })

  const firstHitGoalCount = goals.filter((g) => g.kind === 'first-hit').length

  return {
    generatedAt: now.toISOString(),
    activeRuleCount: active.length,
    reachableRuleCount: firstHitGoalCount,
    goalCount: goals.length,
    firstHitGoalCount,
    blockGoalCount: goals.length - firstHitGoalCount,
    coveredGoalCount: goals.length - uncovered.size,
    goals,
    samples,
  }
}

/** 导出回归样例集为 JSON 文本（复制 / 下载共用） */
export function exportRegression(result: RegressionResult): string {
  return JSON.stringify(result, null, 2)
}
