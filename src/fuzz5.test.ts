/**
 * 策略回归样例生成器模糊对照：在缩小的报文空间（10.1.0.0/24 × 端口 0..63
 * × TCP/UDP）上逐报文暴力首命中，与 generateRegressionSamples 对照：
 *   - 覆盖目标集合（首命中目标 + 阻挡见证目标）与暴力枚举完全一致；
 *   - 每条样例的首命中规则 / 动作与暴力结果一致；
 *   - 样例声称覆盖的每个目标都真实（阻挡见证报文同时落在被阻挡规则声明区域内）；
 *   - 全部目标均被覆盖，且样例数不超过目标数（紧凑性上界）；
 *   - 同一输入两次生成结果一致（确定性）。
 */
import assert from 'node:assert'
import { generateRegressionSamples } from './audit/regression'
import { validateRules } from './audit/engine'
import { ipv4ToInt } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

function randomCidr(): string {
  const hostBits = rand(5) // /24 .. /28
  const prefix = 24 + hostBits
  const size = 2 ** hostBits
  const base = rand(256 / size) * size
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const bad = rand(8) === 0 // 约 1/8 概率非法 / 停用，检验排除语义
    const a = rand(64)
    const b = a + rand(64 - a)
    return {
      id: `f${i}`,
      name: `R${i}`,
      cidr: bad && rand(2) === 0 ? '10.1.0.5/24' : randomCidr(),
      portStart: String(a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(2)],
      enabled: bad && rand(2) === 0 ? false : true,
    }
  })
}

const ALL_PACKETS: Array<{ ip: number; port: number; proto: number; name: string }> = []
for (let ip = 0; ip < 256; ip++) {
  for (let port = 0; port < 64; port++) {
    for (let proto = 0; proto < 2; proto++) {
      ALL_PACKETS.push({
        ip: ipv4ToInt(`10.1.0.${ip}`),
        port,
        proto,
        name: proto === 0 ? 'TCP' : 'UDP',
      })
    }
  }
}

function covers(
  r: { ipStart: number; ipEnd: number; portStart: number; portEnd: number; protocol: string },
  ip: number,
  port: number,
  protoName: string,
): boolean {
  return (
    ip >= r.ipStart &&
    ip <= r.ipEnd &&
    port >= r.portStart &&
    port <= r.portEnd &&
    (r.protocol === 'ANY' || r.protocol === protoName)
  )
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const rules = makeRules(1 + rand(8))
  const { valid } = validateRules(rules)
  const active = valid.filter((r) => r.enabled)

  // 暴力：逐报文首命中（active 下标，-1 = 未命中）
  const owners = ALL_PACKETS.map((pkt) => {
    for (let pos = 0; pos < active.length; pos++) {
      if (covers(active[pos], pkt.ip, pkt.port, pkt.name)) return pos
    }
    return -1
  })

  // 暴力目标集：首命中目标（有报文首命中的规则）+ 阻挡见证目标
  // （存在报文首命中 b 且被更靠后的 s 声明 → 关系 (b, s)）
  const bruteGoals = new Set<string>()
  ALL_PACKETS.forEach((pkt, pi) => {
    const b = owners[pi]
    if (b === -1) return
    bruteGoals.add(`hit:${active[b].id}`)
    for (let s = b + 1; s < active.length; s++) {
      if (covers(active[s], pkt.ip, pkt.port, pkt.name)) {
        bruteGoals.add(`block:${active[b].id}:${active[s].id}`)
      }
    }
  })

  const result = generateRegressionSamples(rules)
  const again = generateRegressionSamples(rules)
  assert.deepEqual(
    result.goals.map((g) => g.id),
    again.goals.map((g) => g.id),
    `round ${round}: 目标集不确定`,
  )
  assert.deepEqual(
    result.samples.map((s) => s.packet),
    again.samples.map((s) => s.packet),
    `round ${round}: 样例不确定`,
  )

  // 目标集合与暴力枚举一致
  const engineGoals = new Set(result.goals.map((g) => g.id))
  assert.deepEqual(engineGoals, bruteGoals, `round ${round}: 目标集不一致 ${JSON.stringify(rules)}`)
  assert.equal(result.activeRuleCount, active.length)
  assert.equal(
    result.reachableRuleCount,
    new Set(owners.filter((o) => o !== -1)).size,
  )

  // 全部目标被覆盖；样例数不超过目标数；无空样例
  assert.equal(result.coveredGoalCount, result.goalCount)
  if (result.goalCount === 0) {
    assert.equal(result.samples.length, 0)
    rounds++
    continue
  }
  assert.ok(result.samples.length >= 1)
  assert.ok(result.samples.length <= result.goalCount)

  const goalById = new Map(result.goals.map((g) => [g.id, g]))
  const covered = new Set<string>()
  for (const sample of result.samples) {
    assert.ok(sample.coveredGoalIds.length > 0, `round ${round}: 存在不覆盖任何目标的样例`)
    const pkt = {
      ip: ipv4ToInt(sample.packet.srcIp),
      port: sample.packet.srcPort,
      name: sample.packet.protocol,
    }
    // 暴力首命中核对样例的预期命中规则与动作
    let hitPos = -1
    for (let pos = 0; pos < active.length; pos++) {
      if (covers(active[pos], pkt.ip, pkt.port, pkt.name)) {
        hitPos = pos
        break
      }
    }
    assert.ok(hitPos !== -1, `round ${round}: 样例未命中任何规则`)
    assert.equal(active[hitPos].id, sample.matchedRuleId)
    assert.equal(active[hitPos].action, sample.action)
    // 声称覆盖的每个目标都真实
    for (const goalId of sample.coveredGoalIds) {
      const goal = goalById.get(goalId)
      assert.ok(goal, `round ${round}: 样例声称覆盖未知目标 ${goalId}`)
      assert.equal(goal!.hitterRuleId, sample.matchedRuleId)
      if (goal!.kind === 'block') {
        const blocked = active.find((r) => r.id === goal!.blockedRuleId)!
        assert.ok(
          covers(blocked, pkt.ip, pkt.port, pkt.name),
          `round ${round}: 阻挡见证样例未落在被阻挡规则声明区域内`,
        )
        // 被阻挡规则必须确实位于阻挡方之后
        assert.ok(active.indexOf(blocked) > hitPos)
      }
      covered.add(goalId)
    }
  }
  // 样例集实际覆盖全部目标
  assert.deepEqual(covered, engineGoals, `round ${round}: 样例集未覆盖全部目标`)
  // coveredBy 与样例登记一致
  for (const goal of result.goals) {
    assert.ok(goal.coveredBy >= 0)
    assert.ok(result.samples[goal.coveredBy].coveredGoalIds.includes(goal.id))
  }

  rounds++
}
console.log(`策略回归样例生成器模糊对照 ${rounds} 轮全部通过 ✔`)
