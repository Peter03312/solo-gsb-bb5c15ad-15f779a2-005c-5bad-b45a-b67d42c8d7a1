/**
 * 策略回归样例生成器自检：覆盖目标构造（首命中 / 阻挡见证）、
 * 确定性贪心（未覆盖目标数最多优先、协议/IP/端口升序平局）、
 * 样例可复现、停用 / 非法规则排除、空规则集提示。
 */
import assert from 'node:assert'
import { exportRegression, generateRegressionSamples } from './audit/regression'
import { validateRules } from './audit/engine'
import { ipv4ToInt } from './audit/iputil'
import type { RuleInput } from './audit/types'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: `g${seq++}`,
    name: partial.name ?? `G${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

/** 暴力首命中：返回报文实际命中的规则（合法且启用，按顺序） */
function bruteFirstHit(
  rules: RuleInput[],
  pkt: { srcIp: string; srcPort: number; protocol: string },
) {
  const { valid } = validateRules(rules)
  const active = valid.filter((r) => r.enabled)
  const ip = ipv4ToInt(pkt.srcIp)
  return active.find(
    (r) =>
      ip >= r.ipStart &&
      ip <= r.ipEnd &&
      pkt.srcPort >= r.portStart &&
      pkt.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === pkt.protocol),
  )
}

/** 报文是否被某条规则的声明区域覆盖 */
function declaredBy(
  rule: RuleInput,
  pkt: { srcIp: string; srcPort: number; protocol: string },
): boolean {
  const { valid } = validateRules([rule])
  if (valid.length === 0) return false
  const r = valid[0]
  const ip = ipv4ToInt(pkt.srcIp)
  return (
    ip >= r.ipStart &&
    ip <= r.ipEnd &&
    pkt.srcPort >= r.portStart &&
    pkt.srcPort <= r.portEnd &&
    (r.protocol === 'ANY' || r.protocol === pkt.protocol)
  )
}

/** 全量校验：目标全覆盖、样例可复现、声称的覆盖关系真实 */
function assertResultSound(rules: RuleInput[], result: ReturnType<typeof generateRegressionSamples>) {
  // 全部目标都被覆盖，且 coveredBy 与样例的 coveredGoalIds 互相一致
  assert.equal(result.coveredGoalCount, result.goalCount)
  for (const goal of result.goals) {
    assert.ok(goal.coveredBy >= 0, `目标 ${goal.description} 未被覆盖`)
    const sample = result.samples[goal.coveredBy]
    assert.ok(sample.coveredGoalIds.includes(goal.id), `样例未登记目标 ${goal.id}`)
  }
  // 每条样例至少覆盖一个目标（无冗余样例）
  for (const sample of result.samples) {
    assert.ok(sample.coveredGoalIds.length > 0)
  }
  // 样例报文可复现：暴力首命中必须命中所述规则与动作
  for (const sample of result.samples) {
    const hit = bruteFirstHit(rules, sample.packet)
    assert.ok(hit, `样例 ${JSON.stringify(sample.packet)} 未命中任何规则`)
    assert.equal(hit!.id, sample.matchedRuleId)
    assert.equal(hit!.action, sample.action)
  }
  // 声称覆盖的每个目标都真实：首命中目标要求命中该规则；
  // 阻挡见证目标要求命中阻挡方、且报文同时落在被阻挡规则的声明区域内
  const byId = new Map(rules.map((r) => [r.id, r]))
  for (const sample of result.samples) {
    for (const goalId of sample.coveredGoalIds) {
      const goal = result.goals.find((g) => g.id === goalId)!
      assert.equal(goal.hitterRuleId, sample.matchedRuleId)
      if (goal.kind === 'block') {
        const blocked = byId.get(goal.blockedRuleId!)!
        assert.ok(
          declaredBy(blocked, sample.packet),
          `样例未落在被阻挡规则 ${goal.blockedRuleName} 的声明区域内`,
        )
      }
    }
  }
}

test('单条规则：一个首命中目标，一条样例全覆盖', () => {
  const rules = [rule({ name: 'only', cidr: '10.0.0.0/8', action: 'allow' })]
  const result = generateRegressionSamples(rules)
  assert.equal(result.activeRuleCount, 1)
  assert.equal(result.reachableRuleCount, 1)
  assert.equal(result.goalCount, 1)
  assert.equal(result.firstHitGoalCount, 1)
  assert.equal(result.blockGoalCount, 0)
  assert.equal(result.samples.length, 1)
  const s = result.samples[0]
  assert.equal(s.matchedRuleName, 'only')
  assert.equal(s.action, 'allow')
  assert.deepEqual(s.coveredGoalIds, [result.goals[0].id])
  assertResultSound(rules, result)
})

test('完全遮蔽：一条样例同时覆盖首命中目标与阻挡见证目标（紧凑）', () => {
  const rules = [
    rule({ name: 'A', cidr: '10.0.0.0/8', action: 'deny' }),
    rule({ name: 'B', cidr: '10.0.0.0/8', action: 'allow' }),
  ]
  const result = generateRegressionSamples(rules)
  // B 完全遮蔽：只有 hit:A 与 block:(A→B) 两个目标
  assert.equal(result.reachableRuleCount, 1)
  assert.equal(result.goalCount, 2)
  assert.equal(result.firstHitGoalCount, 1)
  assert.equal(result.blockGoalCount, 1)
  // 一个报文即可同时见证两者 → 样例集只有一条
  assert.equal(result.samples.length, 1)
  const s = result.samples[0]
  assert.equal(s.matchedRuleName, 'A')
  assert.equal(s.coveredGoalIds.length, 2)
  const block = result.goals.find((g) => g.kind === 'block')!
  assert.equal(block.hitterRuleName, 'A')
  assert.equal(block.blockedRuleName, 'B')
  assertResultSound(rules, result)
})

test('共同覆盖：两组阻挡关系分别被见证，样例数等于首命中规则数', () => {
  const rules = [
    rule({ name: 'lo1', cidr: '10.0.0.0/25' }),
    rule({ name: 'lo2', cidr: '10.0.0.128/25' }),
    rule({ name: 'cover', cidr: '10.0.0.0/24' }),
  ]
  const result = generateRegressionSamples(rules)
  // 目标：hit:lo1、hit:lo2、block:(lo1→cover)、block:(lo2→cover)
  assert.equal(result.goalCount, 4)
  assert.equal(result.firstHitGoalCount, 2)
  assert.equal(result.blockGoalCount, 2)
  // lo1 / lo2 区域互斥，任何报文至多见证其中一组 → 至少需要 2 条样例
  assert.equal(result.samples.length, 2)
  assertResultSound(rules, result)
})

test('贪心优先多目标报文：一个报文覆盖首命中 + 阻挡见证时只生成一条', () => {
  // R1 ANY 全网；R2 TCP 10/8 被 R1 完全遮蔽
  // R1 在 10/8 的 TCP 单元同时覆盖 hit:R1 与 block:(R1→R2)，UDP 单元只覆盖 hit:R1
  const rules = [
    rule({ name: 'R1', cidr: '0.0.0.0/0', action: 'allow' }),
    rule({ name: 'R2', cidr: '10.0.0.0/8', protocol: 'TCP', action: 'deny' }),
  ]
  const result = generateRegressionSamples(rules)
  assert.equal(result.goalCount, 2)
  assert.equal(result.samples.length, 1)
  // 贪心必须选中 10/8 内的 TCP 报文（唯一覆盖 2 个目标的候选）
  const s = result.samples[0]
  assert.equal(s.packet.protocol, 'TCP')
  const ip = ipv4ToInt(s.packet.srcIp)
  assert.ok(ip >= ipv4ToInt('10.0.0.0') && ip <= ipv4ToInt('10.255.255.255'))
  assertResultSound(rules, result)
})

test('平局按协议 / IP / 端口升序：同等覆盖数时 TCP 与更小的 IP 优先', () => {
  // R1 的 TCP 下半区单元与 UDP 上半区单元覆盖数相同（各 2）：
  // 第一轮必须选 TCP 报文；第二轮选 UDP 报文
  const rules = [
    rule({ name: 'base', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ name: 'tcp-half', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'udp-half', cidr: '10.0.0.128/25', protocol: 'UDP', action: 'deny' }),
  ]
  const result = generateRegressionSamples(rules)
  assert.equal(result.goalCount, 3) // hit:base + 两组阻挡见证
  assert.equal(result.samples.length, 2)
  assert.equal(result.samples[0].packet.protocol, 'TCP')
  assert.equal(result.samples[1].packet.protocol, 'UDP')
  // 第一轮 TCP 报文落在下半区（阻挡 tcp-half 的见证）
  const ip0 = ipv4ToInt(result.samples[0].packet.srcIp)
  assert.ok(ip0 >= ipv4ToInt('10.0.0.0') && ip0 <= ipv4ToInt('10.0.0.127'))
  const ip1 = ipv4ToInt(result.samples[1].packet.srcIp)
  assert.ok(ip1 >= ipv4ToInt('10.0.0.128') && ip1 <= ipv4ToInt('10.0.0.255'))

  // 纯 IP 平局：两条互斥 /25 各自遮蔽后续规则，第一条样例命中 IP 最小者
  const rules2 = [
    rule({ name: 'hi', cidr: '10.0.0.128/25', protocol: 'TCP' }),
    rule({ name: 'lo', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ name: 'tail', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' }),
  ]
  const result2 = generateRegressionSamples(rules2)
  assert.equal(result2.samples.length, 2)
  assert.equal(result2.samples[0].matchedRuleName, 'lo')
  assert.equal(result2.samples[1].matchedRuleName, 'hi')
  assertResultSound(rules, result)
  assertResultSound(rules2, result2)
})

test('端口维度的阻挡关系：一个端口单元同时见证两组阻挡', () => {
  // R1 只占 80 端口；R2 全端口（夺走其余端口）；R3 也只声明 80 端口
  const rules = [
    rule({ name: 'web', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'rest', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'web2', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'log' }),
  ]
  const result = generateRegressionSamples(rules)
  // 目标：hit:web、hit:rest、block:(web→rest)、block:(web→web2)
  assert.equal(result.goalCount, 4)
  assert.equal(result.blockGoalCount, 2)
  // 80 端口单元一次覆盖 3 个目标；其余端口单元覆盖 hit:rest → 共 2 条样例
  assert.equal(result.samples.length, 2)
  assert.equal(result.samples[0].packet.srcPort, 80)
  assert.equal(result.samples[0].coveredGoalIds.length, 3)
  assert.notEqual(result.samples[1].packet.srcPort, 80)
  assertResultSound(rules, result)
})

test('停用与非法规则不参与生成：不产生目标、不影响计数', () => {
  const rules = [
    rule({ name: 'live', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ name: 'off', cidr: '0.0.0.0/0', action: 'deny', enabled: false }),
    rule({ name: 'bad', cidr: '10.0.0.5/24', action: 'allow' }),
  ]
  const result = generateRegressionSamples(rules)
  assert.equal(result.activeRuleCount, 1)
  assert.equal(result.goalCount, 1)
  assert.equal(result.goals[0].kind, 'first-hit')
  assert.equal(result.goals[0].hitterRuleName, 'live')
  assert.equal(result.samples.length, 1)
  assertResultSound(rules, result)
})

test('无合法且启用的规则：目标与样例均为空，计数为零', () => {
  for (const rules of [
    [],
    [rule({ name: 'off', enabled: false })],
    [rule({ name: 'bad', cidr: '10.0.0.5/24' })],
  ]) {
    const result = generateRegressionSamples(rules)
    assert.equal(result.activeRuleCount, 0)
    assert.equal(result.reachableRuleCount, 0)
    assert.equal(result.goalCount, 0)
    assert.equal(result.coveredGoalCount, 0)
    assert.equal(result.samples.length, 0)
    assert.equal(result.goals.length, 0)
  }
})

test('结果确定可复现：同一规则集两次生成完全一致', () => {
  const rules = [
    rule({ name: 'a', cidr: '10.0.0.0/8', portStart: '1024', portEnd: '65535', protocol: 'TCP' }),
    rule({ name: 'b', cidr: '10.0.0.0/16', portStart: '80', portEnd: '8080', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'c', cidr: '172.16.0.0/25', protocol: 'UDP', action: 'deny' }),
    rule({ name: 'd', cidr: '172.16.0.128/25', protocol: 'UDP', action: 'deny' }),
    rule({ name: 'e', cidr: '172.16.0.0/24', protocol: 'UDP' }),
    rule({ name: 'f', cidr: '0.0.0.0/0', action: 'allow' }),
  ]
  const now = new Date('2026-09-18T00:00:00Z')
  const r1 = generateRegressionSamples(rules, now)
  const r2 = generateRegressionSamples(rules, now)
  assert.deepEqual(r1, r2)
  assert.ok(r1.samples.length >= 3)
  assertResultSound(rules, r1)
})

test('导出 JSON：可解析且包含摘要、目标与样例', () => {
  const rules = [
    rule({ name: 'A', cidr: '10.0.0.0/8' }),
    rule({ name: 'B', cidr: '10.0.0.0/8' }),
  ]
  const result = generateRegressionSamples(rules)
  const parsed = JSON.parse(exportRegression(result))
  assert.equal(parsed.goalCount, 2)
  assert.equal(parsed.samples.length, 1)
  assert.equal(parsed.goals.length, 2)
  assert.equal(parsed.samples[0].matchedRuleName, 'A')
  assert.ok(parsed.samples[0].packet.srcIp)
  assert.ok(parsed.generatedAt)
})

console.log(`\n策略回归样例生成器 ${passed} 项测试通过 ✔`)
