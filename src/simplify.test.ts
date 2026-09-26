/**
 * 无损精简引擎自检：逐条模拟删除的安全判定、接管精确区域、
 * 代表报文可复现、未命中独立结果、停用 / 非法 / 无流量跳过。
 */
import assert from 'node:assert'
import { analyzeSimplify } from './audit/simplify'
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
    id: `s${seq++}`,
    name: partial.name ?? `S${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

function candidate(result: ReturnType<typeof analyzeSimplify>, name: string) {
  const item = result.items.find((i) => i.kind === 'candidate' && i.ruleName === name)
  assert.ok(item, `缺少规则 ${name} 的分析项`)
  if (item!.kind !== 'candidate') throw new Error(`${name} 不是候选条目`)
  return item!
}

function skipped(result: ReturnType<typeof analyzeSimplify>, name: string) {
  const item = result.items.find((i) => i.ruleName === name)
  assert.ok(item, `缺少规则 ${name}`)
  if (item!.kind !== 'skipped') throw new Error(`${name} 应被跳过`)
  return item!
}

test('完全重复且动作相同的规则：前者可由后者同动作接管而安全删除，后者无流量被跳过', () => {
  const rules = [
    rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ name: 'B', cidr: '10.0.0.0/8', action: 'allow' }),
  ]
  const result = analyzeSimplify(rules)
  // 删除 A 后 B 以相同动作接管全部 10/8 → A 可安全删除
  const a = candidate(result, 'A')
  assert.equal(a.safe, true)
  assert.equal(a.conflicts.length, 0)
  assert.equal(a.takeovers.length, 1)
  assert.equal(a.takeovers[0].ruleName, 'B')
  assert.equal(a.takeovers[0].size, a.effectiveSize)

  // B 完全遮蔽、无有效流量 → 跳过
  const b = skipped(result, 'B')
  assert.equal(b.reason, 'no-traffic')
  assert.equal(result.safeCount, 1)
})

test('有相同动作后续规则完整接管的规则可安全删除，区域与代表报文精确', () => {
  // narrow 先命中一个窄区域；删除后 broad（相同动作）接管同一区域
  const rules = [
    rule({ name: 'narrow', cidr: '10.0.0.0/16', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'broad', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ name: 'outside', cidr: '0.0.0.0/0', action: 'deny' }),
  ]
  const result = analyzeSimplify(rules)
  const narrow = candidate(result, 'narrow')
  assert.equal(narrow.safe, true)
  assert.equal(narrow.conflicts.length, 0)
  assert.equal(narrow.takeovers.length, 1)
  const take = narrow.takeovers[0]
  assert.equal(take.ruleName, 'broad')
  assert.equal(take.action, 'allow')
  // 接管空间精确为 narrow 的有效流量：65536 IP × 1 端口 × 1 协议
  assert.equal(take.size, 65536)
  assert.equal(take.size, narrow.effectiveSize)
  // 精确区域：TCP，端口 80，CIDR 10.0.0.0/16
  assert.equal(take.regions.length, 1)
  assert.equal(take.regions[0].protocol, 'TCP')
  assert.deepEqual(take.regions[0].rows, [
    { portStart: 80, portEnd: 80, cidrs: ['10.0.0.0/16'], size: 65536 },
  ])
  // 代表报文可复现：暴力首命中核对
  const p = take.packet
  assert.equal(p.protocol, 'TCP')
  assert.equal(p.srcPort, 80)
  const ipNum = ipv4ToInt(p.srcIp)
  assert.ok(ipNum >= ipv4ToInt('10.0.0.0') && ipNum <= ipv4ToInt('10.0.255.255'))
  // 删除 narrow 后的规则集 [broad, outside]：该报文必须命中 broad（allow）
  const { valid: after } = validateRules([rules[1], rules[2]])
  const hitAfter = after.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      p.srcPort >= r.portStart &&
      p.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === p.protocol),
  )
  assert.equal(hitAfter!.name, 'broad')
  // 原规则集：命中 narrow，动作同为 allow
  const { valid: before } = validateRules(rules)
  const hitBefore = before.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      p.srcPort >= r.portStart &&
      p.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === p.protocol),
  )
  assert.equal(hitBefore!.name, 'narrow')
  assert.equal(hitBefore!.action, hitAfter!.action)
})

test('接管规则动作不同 → 不安全，冲突区域与动作精确标注', () => {
  const rules = [
    rule({ name: 'narrow', cidr: '10.0.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'broad-deny', cidr: '10.0.0.0/8', action: 'deny' }),
  ]
  const result = analyzeSimplify(rules)
  const narrow = candidate(result, 'narrow')
  assert.equal(narrow.safe, false)
  assert.equal(narrow.takeovers.length, 0)
  assert.equal(narrow.conflicts.length, 1)
  const c = narrow.conflicts[0]
  assert.equal(c.kind, 'action-changed')
  assert.equal(c.ruleName, 'broad-deny')
  assert.equal(c.afterAction, 'deny')
  assert.equal(c.size, 65536)
  assert.deepEqual(c.regions[0].rows[0].cidrs, ['10.0.0.0/16'])
})

test('删除后部分流量未命中、部分被同动作接管 → 不安全（未命中是独立结果）', () => {
  // narrow 覆盖 /16 TCP 全端口；broad 只接管 TCP 80-443，其余删除后未命中
  const rules = [
    rule({ name: 'narrow', cidr: '10.0.0.0/16', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'broad-web', cidr: '10.0.0.0/8', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const result = analyzeSimplify(rules)
  const narrow = candidate(result, 'narrow')
  assert.equal(narrow.safe, false)
  // 一个接管组（80-443）+ 一个未命中组（其余端口）
  assert.equal(narrow.takeovers.length, 1)
  assert.equal(narrow.takeovers[0].size, 65536 * 364)
  assert.equal(narrow.conflicts.length, 1)
  assert.equal(narrow.conflicts[0].kind, 'unmatched')
  assert.equal(narrow.conflicts[0].size, 65536 * (65536 - 364))
  // 合计精确等于有效流量
  const sum =
    narrow.takeovers.reduce((s, g) => s + g.size, 0) +
    narrow.conflicts.reduce((s, g) => s + g.size, 0)
  assert.equal(sum, narrow.effectiveSize)
  // 未命中区域的代表报文端口在 80-443 之外（字典序最小端口原子 = 0 段）
  const up = narrow.conflicts[0].packet
  assert.ok(up.srcPort < 80 || up.srcPort > 443)
  // 该报文在删除后确实不命中任何规则
  const { valid: after } = validateRules([rules[1]])
  const ipNum = ipv4ToInt(up.srcIp)
  const hit = after.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      up.srcPort >= r.portStart &&
      up.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === up.protocol),
  )
  assert.equal(hit, undefined)
})

test('不能仅凭覆盖比例推断：两个后续规则各接管一半且同动作才算安全', () => {
  // narrow 覆盖 /24 TCP；half1/half2 各接管一半（动作必须都相同才安全）
  const same = [
    rule({ name: 'cover', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'half1', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'half2', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ]
  const ok = analyzeSimplify(same)
  const cover = candidate(ok, 'cover')
  assert.equal(cover.safe, true)
  assert.equal(cover.takeovers.length, 2)
  assert.deepEqual(
    cover.takeovers.map((g) => g.ruleName).sort(),
    ['half1', 'half2'],
  )
  // 两块 CIDR 分别精确列出
  const cidrs = cover.takeovers.flatMap((g) => g.regions[0].rows.map((r) => r.cidrs[0])).sort()
  assert.deepEqual(cidrs, ['10.0.0.0/25', '10.0.0.128/25'])
  assert.equal(
    cover.takeovers.reduce((s, g) => s + g.size, 0),
    cover.effectiveSize,
  )

  // half2 改成不同动作：cover 不再安全，冲突精确指向 half2 的半个 /24
  const mixed = [
    same[0],
    same[1],
    { ...same[2], id: `m${seq++}`, action: 'allow' },
  ]
  const bad = analyzeSimplify(mixed)
  const cover2 = candidate(bad, 'cover')
  assert.equal(cover2.safe, false)
  assert.equal(cover2.takeovers.length, 1)
  assert.equal(cover2.takeovers[0].ruleName, 'half1')
  assert.equal(cover2.conflicts.length, 1)
  assert.equal(cover2.conflicts[0].ruleName, 'half2')
  assert.equal(cover2.conflicts[0].size, 128 * 65536)
})

test('无有效流量（完全遮蔽）的规则被跳过，不参与逐条模拟', () => {
  const rules = [
    rule({ name: 'A', cidr: '10.0.0.0/8' }),
    rule({ name: 'shadowed', cidr: '10.0.0.0/8' }),
  ]
  const result = analyzeSimplify(rules)
  const s = skipped(result, 'shadowed')
  assert.equal(s.reason, 'no-traffic')
  assert.equal(result.analyzedCount, 1)
  assert.equal(result.skippedNoTraffic, 1)
})

test('停用与非法规则不参与模拟', () => {
  const rules = [
    rule({ name: 'off', cidr: '10.0.0.0/8', enabled: false }),
    rule({ name: 'bad', cidr: '10.0.0.5/24' }),
    rule({ name: 'live', cidr: '192.168.0.0/16', action: 'deny' }),
  ]
  const result = analyzeSimplify(rules)
  assert.equal(skipped(result, 'off').reason, 'disabled')
  assert.equal(skipped(result, 'bad').reason, 'invalid')
  assert.equal(result.skippedDisabled, 1)
  assert.equal(result.skippedInvalid, 1)
  assert.equal(result.analyzedCount, 1)
  // 停用规则不影响活动规则的原子空间与判定
  const live = candidate(result, 'live')
  assert.equal(live.effectiveSize, 65536 * 65536 * 2)
  assert.equal(live.safe, false) // 删除后全部未命中
  assert.ok(live.conflicts.every((c) => c.kind === 'unmatched'))
})

test('多个不同动作的接管组分别给出区域与代表报文', () => {
  // cover 命中 10.0.0.0/24 TCP 全端口；后续 web(allow,80-443) 与 ssh(deny,22)
  // 两接管组动作都与 cover 不同 → 两个冲突组 + 其余端口未命中
  const rules = [
    rule({ name: 'cover', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'log' }),
    rule({ name: 'web', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'ssh', cidr: '10.0.0.0/24', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
  ]
  const result = analyzeSimplify(rules)
  const cover = candidate(result, 'cover')
  assert.equal(cover.safe, false)
  assert.equal(cover.takeovers.length, 0)
  const byName = new Map(cover.conflicts.map((c) => [c.ruleName ?? 'unmatched', c]))
  assert.equal(byName.get('web')!.size, 256 * 364)
  assert.equal(byName.get('ssh')!.size, 256)
  assert.ok(byName.has('unmatched'))
  // 端口 22 包含在 80-443 之外，首命中的后续规则：ssh（更靠前？顺序：web 在 ssh 前，
  // 22 不匹配 web，只匹配 ssh）
  const sshConflict = byName.get('ssh')!
  assert.equal(sshConflict.packet.srcPort, 22)
  // web 代表报文端口取其区域最小端口原子 = 80
  assert.equal(byName.get('web')!.packet.srcPort, 80)
})

test('ANY 规则删除：TCP / UDP 两个协议维分别由后续规则接管时区域分列', () => {
  const rules = [
    rule({ name: 'any-allow', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ name: 'tcp-take', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
    rule({ name: 'udp-take', cidr: '10.0.0.0/24', protocol: 'UDP', action: 'allow' }),
  ]
  const result = analyzeSimplify(rules)
  const anyRule = candidate(result, 'any-allow')
  assert.equal(anyRule.safe, true)
  const byRule = new Map(anyRule.takeovers.map((g) => [g.ruleName, g]))
  assert.deepEqual([...byRule.keys()].sort(), ['tcp-take', 'udp-take'])
  const protocols = anyRule.takeovers.map((g) => g.regions[0].protocol).sort()
  assert.deepEqual(protocols, ['TCP', 'UDP'])
  assert.equal(
    anyRule.takeovers.reduce((s, g) => s + g.size, 0),
    anyRule.effectiveSize,
  )
})

console.log(`\n无损精简 ${passed} 项测试通过 ✔`)
