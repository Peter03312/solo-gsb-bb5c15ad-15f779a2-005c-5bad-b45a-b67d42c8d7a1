/** 审计引擎自检：node --test 风格的轻量断言脚本（零额外依赖） */
import assert from 'node:assert'
import { audit, parseRulesJson, validateRules } from './audit/engine'
import { movedRules, previewReorder } from './audit/reorder'
import { verifyGoal } from './audit/verify'
import { analyzeSimplify } from './audit/simplify'
import type { RuleInput } from './audit/types'
import { ipv4ToInt, parseCidrStrict } from './audit/iputil'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

// --- CIDR 严格校验 ---
test('严格 CIDR：主机位非零被拒绝', () => {
  assert.throws(() => parseCidrStrict('10.0.0.1/24'), /主机位非零/)
})

test('严格 CIDR：/32 单地址合法', () => {
  assert.doesNotThrow(() => parseCidrStrict('192.168.1.1/32'))
})

test('严格 CIDR：前缀越界 / 格式错误', () => {
  assert.throws(() => parseCidrStrict('10.0.0.0/33'))
  assert.throws(() => parseCidrStrict('10.0.0/8'))
  assert.throws(() => parseCidrStrict('999.0.0.0/8'))
  assert.throws(() => parseCidrStrict('::1/128'))
})

// --- 基础遮蔽 ---
test('相同区域的第二条规则被完全遮蔽', () => {
  const report = audit([
    rule({ name: 'A', cidr: '10.0.0.0/8' }),
    rule({ name: 'B', cidr: '10.0.0.0/8' }),
  ])
  const [a, b] = report.entries
  assert.equal(a.kind, 'valid')
  assert.equal(b.kind, 'valid')
  if (a.kind !== 'valid' || b.kind !== 'valid') return
  assert.equal(a.status, 'reachable')
  assert.equal(b.status, 'fully-shadowed')
  assert.equal(a.effectiveSize, a.declaredSize)
  assert.equal(b.effectiveSize, 0)
  assert.equal(b.shadowSources[0].ruleName, 'A')
  assert.equal(b.shadowedExamples[0].matchedRuleName, 'A')
  assert.equal(b.shadowedExamples[0].kind, 'shadowed')
  assert.equal(b.collectiveCover, false)
})

test('子集规则被完全遮蔽，外层规则部分可达', () => {
  const report = audit([
    rule({ name: 'BIG', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ name: 'SMALL', cidr: '10.1.0.0/16', protocol: 'TCP' }),
  ])
  const [big, small] = report.entries
  if (big.kind !== 'valid' || small.kind !== 'valid') throw new Error('bad kinds')
  assert.equal(small.status, 'fully-shadowed')
  // BIG 在前，所有 10/8 TCP 都命中 BIG，因此 BIG 完整可达
  assert.equal(big.status, 'reachable')
  assert.equal(big.effectiveSize, big.declaredSize)
  assert.equal(small.effectiveSize, 0)
})

test('部分遮蔽：两个 /25 遮蔽一个 /24 的一半', () => {
  const report = audit([
    rule({ name: 'lo1', cidr: '10.0.0.0/25' }),
    rule({ name: 'lo2', cidr: '10.0.0.128/25' }),
    rule({ name: 'cover', cidr: '10.0.0.0/24' }),
  ])
  const cover = report.entries[2]
  if (cover.kind !== 'valid') throw new Error('bad')
  assert.equal(cover.status, 'fully-shadowed')
  assert.equal(cover.collectiveCover, true)
  // 两个来源，各自贡献一半单元
  const sources = cover.shadowSources
  assert.equal(sources.length, 2)
  assert.deepEqual(
    sources.map((s) => s.ruleName).sort(),
    ['lo1', 'lo2'],
  )
  // 两条遮蔽样例分别指向两个来源
  const matched = cover.shadowedExamples.map((e) => e.matchedRuleName).sort()
  assert.deepEqual(matched, ['lo1', 'lo2'])
})

test('部分遮蔽：前序规则只盖住一半，后半仍可达', () => {
  const report = audit([
    rule({ name: 'half', cidr: '10.0.0.0/25' }),
    rule({ name: 'full', cidr: '10.0.0.0/24' }),
  ])
  const full = report.entries[1]
  if (full.kind !== 'valid') throw new Error('bad')
  assert.equal(full.status, 'partial-shadowed')
  // 默认 ANY=TCP+UDP，故按报文空间计比例为 128/256 × 全部端口 × 2 协议 = 1/2 空间，
  // 而按单元计（IP 两半 × 2 协议）遮蔽 2/4、有效 2/4，这里展示的是报文空间比例
  assert.equal(full.effectiveSize, 128 * 65536 * 2)
  assert.equal(full.effectiveRatio, 0.5)
  assert.ok(full.reachableExample)
  assert.equal(full.reachableExample!.srcIp, '10.0.0.129')
  assert.equal(full.shadowedExamples[0].srcIp, '10.0.0.1')
  // 有效区域只含后半个 /24
  const cidrs = full.region.flatMap((g) => g.cidrs)
  assert.ok(cidrs.includes('10.0.0.128/25'))
  assert.ok(!cidrs.some((c) => c.startsWith('10.0.0.0/')))
})

test('协议维与端口维同样参与遮蔽计算', () => {
  const report = audit([
    rule({ name: 'tcp-all', cidr: '10.0.0.0/24', protocol: 'TCP' }),
    rule({ name: 'udp-80', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'UDP' }),
    rule({ name: 'any-all', cidr: '10.0.0.0/24', protocol: 'ANY' }),
  ])
  const [tcp, udp80, any] = report.entries
  if (tcp.kind !== 'valid' || udp80.kind !== 'valid' || any.kind !== 'valid') throw new Error('bad')
  assert.equal(tcp.status, 'reachable')
  assert.equal(udp80.status, 'reachable')
  // any-all 只拿到 UDP 1-79,81-65535
  assert.equal(any.status, 'partial-shadowed')
  const udpRegion = any.region.find((g) => g.protocol === 'UDP')!
  assert.equal(udpRegion.portRanges.length, 2)
  assert.ok(!any.region.some((g) => g.protocol === 'TCP'))
})

test('有效区域大小 = IP × 端口 × 协议，比率正确', () => {
  const report = audit([
    rule({ name: 'p', cidr: '10.0.0.0/24', portStart: '1', portEnd: '100', protocol: 'TCP' }),
    rule({
      name: 'q',
      cidr: '10.0.0.0/24',
      portStart: '1',
      portEnd: '100',
      protocol: 'TCP',
    }),
  ])
  const [p, q] = report.entries
  if (p.kind !== 'valid' || q.kind !== 'valid') throw new Error('bad')
  assert.equal(p.declaredSize, 256 * 100)
  assert.equal(q.effectiveSize, 0)
})

// --- 非法规则 ---
test('非法 CIDR / 端口不参与分析，且保留原下标', () => {
  const report = audit([
    rule({ name: 'good', cidr: '10.0.0.0/8' }),
    rule({ name: 'bad-cidr', cidr: '10.0.0.0/99' }),
    rule({ name: 'bad-port', cidr: '10.0.0.0/8', portStart: '99999', portEnd: '5' }),
    rule({ name: 'after', cidr: '10.0.0.0/8' }),
  ])
  assert.equal(report.entries.length, 4)
  assert.equal(report.entries[1].kind, 'invalid')
  assert.equal(report.entries[2].kind, 'invalid')
  assert.equal(report.entries[3].index, 3)
  const after = report.entries[3]
  if (after.kind !== 'valid') throw new Error('bad')
  assert.equal(after.status, 'fully-shadowed') // 只被 good 遮蔽，非法规则不参与
  assert.equal(after.shadowSources[0].ruleName, 'good')
})

// --- 停用规则 ---
test('停用规则不参与首命中分析：不再遮蔽后续规则，自身标记 disabled', () => {
  const report = audit([
    rule({ name: 'on-top', cidr: '10.0.0.0/8', enabled: false }),
    rule({ name: 'below', cidr: '10.0.0.0/8' }),
  ])
  const [top, below] = report.entries
  if (top.kind !== 'valid' || below.kind !== 'valid') throw new Error('bad')
  assert.equal(top.status, 'disabled')
  assert.equal(top.effectiveSize, 0)
  // 停用规则不遮蔽后续规则
  assert.equal(below.status, 'reachable')
  assert.equal(below.effectiveSize, below.declaredSize)
  assert.equal(report.stats.disabled, 1)
  assert.equal(report.stats.totalDeclaredSize, below.declaredSize)
})

test('停用规则在目标验证与无损精简中均被排除', () => {
  const rules = [
    rule({ name: 'off', cidr: '10.0.0.0/8', enabled: false }),
    rule({ name: 'live', cidr: '192.168.0.0/16', action: 'deny' }),
  ]
  const out = verifyGoal(rules, {
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    expectedAction: 'allow',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  // 停用的 10/8 规则不覆盖目标：整个目标空间未命中
  assert.equal(out.result.validRuleCount, 1)
  assert.equal(out.result.disabledExcluded, 1)
  assert.equal(out.result.unmatchedSize, out.result.totalSize)

  const sim = analyzeSimplify(rules)
  assert.equal(sim.skippedDisabled, 1)
  assert.equal(sim.analyzedCount, 1)
})

test('重新启用停用规则后恢复遮蔽分析', () => {
  const enabled = [
    rule({ name: 'on-top', cidr: '10.0.0.0/8' }),
    rule({ name: 'below', cidr: '10.0.0.0/8' }),
  ]
  const report = audit(enabled)
  assert.equal((report.entries[1] as any).status, 'fully-shadowed')
  assert.equal(report.stats.disabled, 0)
})

// --- 共同覆盖：非规则长方体的补集 ---
test('十字形共同覆盖：两条规则的并集盖住 L 形区域', () => {
  // A: 左半 IP 全端口; B: 右半 IP 的低端口; C: 全 IP 低端口
  const report = audit([
    rule({ name: 'A', cidr: '10.0.0.0/25', portStart: '0', portEnd: '65535' }),
    rule({ name: 'B', cidr: '10.0.0.128/25', portStart: '0', portEnd: '1024' }),
    rule({ name: 'C', cidr: '10.0.0.0/24', portStart: '0', portEnd: '1024' }),
  ])
  const c = report.entries[2]
  if (c.kind !== 'valid') throw new Error('bad')
  assert.equal(c.status, 'fully-shadowed')
  assert.equal(c.collectiveCover, true)
  const names = c.shadowSources.map((s) => s.ruleName).sort()
  assert.deepEqual(names, ['A', 'B'])
})

// --- 示例报文可复现且确实命中所述规则 ---
test('示例报文在首条命中语义下确实命中来源规则', () => {
  const rules = [
    rule({ name: 'deny-ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'allow-all', cidr: '0.0.0.0/0', action: 'allow' }),
  ]
  const report = audit(rules)
  const { valid: normalized } = validateRules(rules)
  const allow = report.entries[1]
  if (allow.kind !== 'valid') throw new Error('bad')
  const ex = allow.shadowedExamples[0]
  assert.equal(ex.protocol, 'TCP')
  assert.equal(ex.srcPort, 22)
  assert.equal(ex.action, 'deny')

  // 模拟首条命中：报文必须命中 ex.matchedRuleIndex 指向的规则
  const ipNum = ipv4ToInt(ex.srcIp)
  const hit = normalized.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ex.srcPort >= r.portStart &&
      ex.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ex.protocol),
  )
  assert.ok(hit, '示例报文必须能匹配某条规则')
  assert.equal(hit!.index, ex.matchedRuleIndex)
  assert.equal(hit!.name, 'deny-ssh')

  // 可达样例同理：命中自身
  const deny = report.entries[0]
  if (deny.kind !== 'valid') throw new Error('bad')
  const ok = deny.reachableExample!
  const hit2 = normalized.find(
    (r) =>
      ipv4ToInt(ok.srcIp) >= r.ipStart &&
      ipv4ToInt(ok.srcIp) <= r.ipEnd &&
      ok.srcPort >= r.portStart &&
      ok.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ok.protocol),
  )
  assert.equal(hit2!.index, deny.index)
})

// --- JSON 导入 ---
test('JSON 导入：数组 / {rules} / 导出报告 三种形态', () => {
  const arr = parseRulesJson(
    JSON.stringify([{ cidr: '10.0.0.0/8', portStart: 1, portEnd: 1024, protocol: 'tcp', action: 'deny' }]),
  )
  assert.equal(arr.errors.length, 0)
  assert.equal(arr.rules[0].protocol, 'TCP') // 导入时归一化大小写

  const wrapped = parseRulesJson(JSON.stringify({ rules: [{ cidr: '0.0.0.0/0', action: 'x' }] }))
  assert.equal(wrapped.rules.length, 1)

  const report = audit([rule({ name: 'A' }), rule({ name: 'B' })])
  const roundTrip = parseRulesJson(JSON.stringify(report))
  assert.equal(roundTrip.rules.length, 2)
})

test('JSON 导入：非法 JSON 报错', () => {
  const r = parseRulesJson('{not json')
  assert.ok(r.errors[0].includes('JSON 解析失败'))
})

// --- 调序影响预览 ---
test('调序预览：重叠规则互换位置产生动作变化与可复现样例', () => {
  const deny = rule({ name: 'deny-ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' })
  const allow = rule({ name: 'allow-all', cidr: '0.0.0.0/0', action: 'allow' })
  const current = [deny, allow]
  const candidate = [allow, deny]
  const p = previewReorder(current, candidate)

  assert.equal(p.hasDifference, true)
  assert.equal(p.actionChanges.length, 1)
  const ch = p.actionChanges[0]
  assert.equal(ch.oldRuleId, deny.id)
  assert.equal(ch.newRuleId, allow.id)
  assert.equal(ch.oldAction, 'deny')
  assert.equal(ch.newAction, 'allow')
  // 样例报文落在重叠区域 SSH 上：TCP 192.168.x.x:22
  assert.equal(ch.packet.protocol, 'TCP')
  assert.equal(ch.packet.srcPort, 22)
  const ipNum = ipv4ToInt(ch.packet.srcIp)
  assert.ok(ipNum >= ipv4ToInt('192.168.0.0') && ipNum <= ipv4ToInt('192.168.255.255'))
  // 变化空间 = /16 个 IP × 1 端口 × 1 协议
  assert.equal(ch.size, 65536)

  // 用暴力首命中复现：候选顺序下该报文必须命中 allow-all（allow）
  const { valid: cand } = validateRules(candidate)
  const hitCand = cand.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ch.packet.srcPort >= r.portStart &&
      ch.packet.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ch.packet.protocol),
  )
  assert.equal(hitCand!.id, allow.id)
  // 当前顺序下命中 deny-ssh（deny）
  const { valid: old } = validateRules(current)
  const hitOld = old.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ch.packet.srcPort >= r.portStart &&
      ch.packet.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ch.packet.protocol),
  )
  assert.equal(hitOld!.id, deny.id)

  // 逐规则视图：两条规则的状态 / 有效空间都翻转
  const denyView = p.rules.find((v) => v.id === deny.id)!
  assert.equal(denyView.oldStatus, 'reachable')
  assert.equal(denyView.newStatus, 'fully-shadowed')
  assert.equal(denyView.sizeDelta, -65536)
  const allowView = p.rules.find((v) => v.id === allow.id)!
  assert.equal(allowView.sizeDelta, 65536)
})

test('调序预览：不相交规则换位仅有序号变化、无实际差异', () => {
  const a = rule({ name: 'A', cidr: '10.0.0.0/8', action: 'deny' })
  const b = rule({ name: 'B', cidr: '192.168.0.0/16', action: 'allow' })
  const current = [a, b]
  const candidate = [b, a]
  const p = previewReorder(current, candidate)

  assert.equal(p.hasDifference, false)
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 0)
  assert.equal(p.totalReassignedSize, 0)
  assert.equal(p.rules.length, 2)
  assert.ok(p.rules.every((v) => v.moved && !v.auditChanged))
  assert.equal(p.rules.find((v) => v.id === b.id)!.oldIndex, 1)
  assert.equal(p.rules.find((v) => v.id === b.id)!.newIndex, 0)
  // 状态与有效空间保持不变
  assert.ok(p.rules.every((v) => v.oldStatus === v.newStatus && v.sizeDelta === 0))
})

test('调序预览：动作相同的规则互换只产生 sameActionChanges', () => {
  const a = rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })
  const b = rule({ name: 'B', cidr: '0.0.0.0/0', action: 'allow' })
  const p = previewReorder([a, b], [b, a])
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 1)
  assert.equal(p.hasDifference, true)
  assert.equal(p.sameActionChanges[0].size, 2 ** 24 * 65536 * 2)
})

test('调序预览：非法规则跟随移动但继续不参与分析', () => {
  const a = rule({ name: 'good-a', cidr: '10.0.0.0/8', action: 'allow' })
  const bad = rule({ name: 'bad', cidr: '10.0.0.5/24', action: 'allow' })
  const b = rule({ name: 'good-b', cidr: '192.168.0.0/16', action: 'deny' })
  const current = [a, bad, b]
  // 把非法规则从 #2 拖到 #3：[a, b, bad]
  const candidate = movedRules(current, 1, 2)
  assert.deepEqual(candidate.map((r) => r.id), [a.id, b.id, bad.id])
  const p = previewReorder(current, candidate)

  const badView = p.rules.find((v) => v.id === bad.id)!
  assert.equal(badView.oldStatus, 'invalid')
  assert.equal(badView.newStatus, 'invalid')
  assert.equal(badView.moved, true)
  assert.equal(badView.oldIndex, 1)
  assert.equal(badView.newIndex, 2)
  assert.equal(badView.sizeDelta, 0)
  // 合法规则区域不相交：没有任何流量归属变化
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 0)
})

test('调序预览：未移动的规则也会被上移到其前面的规则遮蔽（影响不限于被拖动规则）', () => {
  // a 与 c 重叠（a 区域更窄），b 与两者不相交；a/b 同动作，c 为兜底 deny
  const a = rule({ name: 'a-web', cidr: '10.0.0.0/24', action: 'allow' })
  const b = rule({ name: 'b-other', cidr: '192.168.0.0/16', action: 'allow' })
  const c = rule({ name: 'c-deny-all', cidr: '0.0.0.0/0', action: 'deny' })
  const current = [a, b, c]
  // 把 c 从 #3 拖到 a 与 b 之间：a(index 0) 位置不变，b 下移
  const candidate = movedRules(current, 2, 1)
  assert.deepEqual(candidate.map((r) => r.id), [a.id, c.id, b.id])
  const p = previewReorder(current, candidate)

  // a 未移动，但 c 现在不在其前方，状态不变；真正被影响的是下移的 b
  const aView = p.rules.find((v) => v.id === a.id)
  if (aView) {
    assert.equal(aView.moved, false)
    assert.equal(aView.auditChanged, false)
  }
  // b 下移一位，前面插入 c(deny all)：由可达变为完全遮蔽
  const bView = p.rules.find((v) => v.id === b.id)!
  assert.equal(bView.moved, true)
  assert.equal(bView.oldStatus, 'reachable')
  assert.equal(bView.newStatus, 'fully-shadowed')
  assert.ok(bView.sizeDelta < 0)
  // 流量首命中动作：allow(b) → deny(c)
  assert.ok(p.actionChanges.length >= 1)
  const acts = new Set(
    p.actionChanges.map((ch) => `${ch.oldRuleId}>${ch.newRuleId}:${ch.oldAction}>${ch.newAction}`),
  )
  assert.ok(acts.has(`${b.id}>${c.id}:allow>deny`))
  const ch = p.actionChanges.find((x) => x.oldRuleId === b.id && x.newRuleId === c.id)!
  assert.equal(ch.packet.protocol, 'TCP')
  const ipNum = ipv4ToInt(ch.packet.srcIp)
  assert.ok(ipNum >= ipv4ToInt('192.168.0.0') && ipNum <= ipv4ToInt('192.168.255.255'))
})

// --- 策略目标验证 ---
const GOAL_BASE = {
  cidr: '10.0.0.0/8',
  portStart: '0',
  portEnd: '65535',
  protocol: 'ANY',
  expectedAction: 'allow',
}

test('目标验证：非法目标被拒绝（CIDR / 端口 / 协议 / 动作）', () => {
  const badCidr = verifyGoal([], { ...GOAL_BASE, cidr: '10.0.0.1/24' })
  assert.equal(badCidr.ok, false)
  if (!badCidr.ok) assert.ok(badCidr.errors.some((e) => e.includes('主机位非零')))

  const badPort = verifyGoal([], { ...GOAL_BASE, portStart: '65535', portEnd: '0' })
  assert.equal(badPort.ok, false)
  if (!badPort.ok) assert.ok(badPort.errors.some((e) => e.includes('倒置')))

  assert.equal(verifyGoal([], { ...GOAL_BASE, protocol: 'ICMP' }).ok, false)
  assert.equal(verifyGoal([], { ...GOAL_BASE, expectedAction: '  ' }).ok, false)
  assert.equal(verifyGoal([], { ...GOAL_BASE, cidr: '' }).ok, false)
})

test('目标验证：目标边界落在规则原子块内部时精确切分', () => {
  const out = verifyGoal(
    [rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })],
    { ...GOAL_BASE, cidr: '10.0.0.0/16', expectedAction: 'deny' },
  )
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  // 目标 /16 在规则 /8 原子内部：违规区域必须精确为 /16，而非整个 /8
  assert.equal(r.totalSize, 65536 * 65536 * 2)
  assert.equal(r.conformSize, 0)
  assert.equal(r.unmatchedSize, 0)
  assert.equal(r.actionGroups.length, 1)
  const g = r.actionGroups[0]
  assert.equal(g.action, 'allow')
  assert.equal(g.size, 65536 * 65536 * 2)
  assert.equal(g.regions.length, 2) // ANY → TCP / UDP 各一组
  for (const reg of g.regions) {
    assert.deepEqual(
      reg.rows.map((row) => row.cidrs),
      [['10.0.0.0/16']],
    )
    assert.equal(reg.size, 65536 * 65536)
  }
})

test('目标验证：全部符合期望', () => {
  const out = verifyGoal(
    [rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })],
    { ...GOAL_BASE, cidr: '10.0.0.0/16', expectedAction: 'allow' },
  )
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.conformSize, r.totalSize)
  assert.equal(r.conformRatio, 1)
  assert.equal(r.otherActionSize, 0)
  assert.equal(r.unmatchedSize, 0)
  assert.equal(r.unmatched, null)
  assert.equal(r.actionGroups.length, 0)
})

test('目标验证：命中其他动作与未命中分类、精确区域与代表报文', () => {
  const rules = [
    rule({ name: 'deny-half', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'deny' }),
  ]
  const out = verifyGoal(rules, {
    ...GOAL_BASE,
    cidr: '10.0.0.0/24',
    protocol: 'TCP',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.totalSize, 256 * 65536)
  assert.equal(r.conformSize, 0)
  assert.equal(r.otherActionSize, 128 * 65536)
  assert.equal(r.unmatchedSize, 128 * 65536)

  // 违规分组：deny，区域精确为前半 /25
  assert.equal(r.actionGroups.length, 1)
  const g = r.actionGroups[0]
  assert.equal(g.action, 'deny')
  assert.equal(g.regions.length, 1)
  assert.equal(g.regions[0].protocol, 'TCP')
  assert.deepEqual(g.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.0/25'], size: 128 * 65536 },
  ])

  // 代表报文可复现：暴力首命中核对确实命中 deny 规则
  const { valid } = validateRules(rules)
  const ex = g.examples[0]
  assert.equal(ex.protocol, 'TCP')
  assert.equal(ex.srcIp, '10.0.0.1')
  const hit = valid.find(
    (rr) =>
      ipv4ToInt(ex.srcIp) >= rr.ipStart &&
      ipv4ToInt(ex.srcIp) <= rr.ipEnd &&
      ex.srcPort >= rr.portStart &&
      ex.srcPort <= rr.portEnd &&
      (rr.protocol === 'ANY' || rr.protocol === ex.protocol),
  )
  assert.equal(hit!.action, 'deny')
  assert.equal(hit!.index, ex.matchedRuleIndex)

  // 未命中代表报文：不被任何规则覆盖；区域精确为后半 /25
  assert.ok(r.unmatched)
  const ux = r.unmatched!.examples[0]
  assert.equal(ux.srcIp, '10.0.0.129')
  const none = valid.find(
    (rr) =>
      ipv4ToInt(ux.srcIp) >= rr.ipStart &&
      ipv4ToInt(ux.srcIp) <= rr.ipEnd &&
      ux.srcPort >= rr.portStart &&
      ux.srcPort <= rr.portEnd &&
      (rr.protocol === 'ANY' || rr.protocol === ux.protocol),
  )
  assert.equal(none, undefined)
  assert.deepEqual(
    r.unmatched!.regions[0].rows.map((row) => row.cidrs),
    [['10.0.0.128/25']],
  )
})

test('目标验证：ANY 分别检查 TCP 与 UDP', () => {
  const out = verifyGoal(
    [rule({ name: 'tcp-only', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })],
    { ...GOAL_BASE, cidr: '10.0.0.0/24' },
  )
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.totalSize, 256 * 65536 * 2)
  assert.equal(r.conformSize, 256 * 65536) // 仅 TCP 符合
  assert.equal(r.unmatchedSize, 256 * 65536) // UDP 无任何规则
  const tcp = r.perProtocol.find((p) => p.protocol === 'TCP')!
  const udp = r.perProtocol.find((p) => p.protocol === 'UDP')!
  assert.equal(tcp.conformSize, 256 * 65536)
  assert.equal(tcp.unmatchedSize, 0)
  assert.equal(udp.conformSize, 0)
  assert.equal(udp.unmatchedSize, 256 * 65536)
  // 未命中代表报文只有 UDP 一个
  assert.equal(r.unmatched!.examples.length, 1)
  assert.equal(r.unmatched!.examples[0].protocol, 'UDP')
})

test('目标验证：非法规则被排除，不参与首命中计算', () => {
  const rules = [
    rule({ name: 'deny', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'bad', cidr: '10.0.0.5/24', action: 'allow' }), // 非法 CIDR
  ]
  const out = verifyGoal(rules, {
    ...GOAL_BASE,
    cidr: '10.0.0.0/24',
    protocol: 'TCP',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.invalidExcluded, 1)
  assert.equal(r.validRuleCount, 1)
  assert.equal(r.actionGroups.length, 1)
  assert.equal(r.actionGroups[0].action, 'deny')
  assert.equal(r.unmatchedSize, 0)
})

test('目标验证：目标端口边界落在规则端口原子内部时精确切分', () => {
  const rules = [
    rule({
      name: 'R',
      cidr: '10.0.0.0/24',
      portStart: '150',
      portEnd: '200',
      protocol: 'TCP',
      action: 'deny',
    }),
  ]
  const out = verifyGoal(rules, {
    ...GOAL_BASE,
    cidr: '10.0.0.0/24',
    portStart: '100',
    portEnd: '199',
    protocol: 'TCP',
    expectedAction: 'deny',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.totalSize, 256 * 100)
  assert.equal(r.conformSize, 256 * 50) // 端口 150-199
  assert.equal(r.unmatchedSize, 256 * 50) // 端口 100-149
  assert.equal(r.unmatched!.regions[0].rows.length, 1)
  assert.deepEqual(r.unmatched!.regions[0].rows[0], {
    portStart: 100,
    portEnd: 149,
    cidrs: ['10.0.0.0/24'],
    size: 256 * 50,
  })
})

test('目标验证：违规区域非矩形时仍精确（不做笛卡尔积近似）', () => {
  const rules = [
    rule({ name: 'R1', cidr: '10.0.0.0/25', portStart: '0', portEnd: '79', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'R2', cidr: '10.0.0.128/25', portStart: '80', portEnd: '65535', protocol: 'TCP', action: 'deny' }),
  ]
  const out = verifyGoal(rules, {
    ...GOAL_BASE,
    cidr: '10.0.0.0/24',
    protocol: 'TCP',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  const g = r.actionGroups[0]
  assert.equal(g.action, 'deny')
  // 左半 × 端口0-79 ∪ 右半 × 端口80-65535：精确大小，而非 /24 × 全端口的近似
  assert.equal(g.size, 128 * 80 + 128 * (65536 - 80))
  assert.ok(g.size !== 256 * 65536)
  const rows = g.regions[0].rows
  assert.equal(rows.length, 2)
  assert.deepEqual(rows[0], {
    portStart: 0,
    portEnd: 79,
    cidrs: ['10.0.0.0/25'],
    size: 128 * 80,
  })
  assert.deepEqual(rows[1], {
    portStart: 80,
    portEnd: 65535,
    cidrs: ['10.0.0.128/25'],
    size: 128 * (65536 - 80),
  })
  // 行大小合计与单元级统计一致；未命中部分同样精确
  assert.equal(rows.reduce((s, row) => s + row.size, 0), g.size)
  assert.equal(r.unmatched!.size, 128 * (65536 - 80) + 128 * 80)
})

test('目标验证：代表报文在首条命中语义下可复现（多规则）', () => {
  const rules = [
    rule({ name: 'deny-ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'allow-all', cidr: '0.0.0.0/0', action: 'allow' }),
  ]
  const out = verifyGoal(rules, {
    ...GOAL_BASE,
    cidr: '192.168.0.0/24',
    protocol: 'TCP',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.unmatchedSize, 0)
  assert.equal(r.otherActionSize, 256) // /24 × 端口 22
  assert.equal(r.conformSize, 256 * 65536 - 256)
  const g = r.actionGroups[0]
  assert.equal(g.action, 'deny')
  const ex = g.examples[0]
  assert.equal(ex.srcPort, 22)
  const { valid } = validateRules(rules)
  const hit = valid.find(
    (rr) =>
      ipv4ToInt(ex.srcIp) >= rr.ipStart &&
      ipv4ToInt(ex.srcIp) <= rr.ipEnd &&
      ex.srcPort >= rr.portStart &&
      ex.srcPort <= rr.portEnd &&
      (rr.protocol === 'ANY' || rr.protocol === ex.protocol),
  )
  assert.equal(hit!.name, 'deny-ssh')
  assert.equal(hit!.index, ex.matchedRuleIndex)
})

test('目标验证：无规则时整个目标空间未命中', () => {
  const out = verifyGoal([], {
    ...GOAL_BASE,
    cidr: '192.168.1.0/24',
    portStart: '80',
    portEnd: '80',
    protocol: 'TCP',
  })
  assert.equal(out.ok, true)
  if (!out.ok) return
  const r = out.result
  assert.equal(r.totalSize, 256)
  assert.equal(r.unmatchedSize, 256)
  assert.equal(r.unmatchedRatio, 1)
  assert.equal(r.conformSize, 0)
  assert.equal(r.actionGroups.length, 0)
  assert.equal(r.unmatched!.examples[0].srcPort, 80)
})

// --- 最小解释集（完全遮蔽规则详情） ---
test('最小解释集：单条前序规则独立全覆盖时返回该规则', () => {
  const report = audit([
    rule({ name: 'A', cidr: '10.0.0.0/8' }),
    rule({ name: 'B', cidr: '10.0.0.0/8' }),
  ])
  const b = report.entries[1]
  if (b.kind !== 'valid') throw new Error('bad')
  assert.equal(b.status, 'fully-shadowed')
  const me = b.minExplanation!
  assert.ok(me)
  assert.equal(me.skipped, false)
  assert.equal(me.candidateCount, 1)
  assert.equal(me.exactLimit, 18)
  assert.equal(me.coveredCells, me.declaredCells)
  assert.equal(me.members.length, 1)
  assert.equal(me.members[0].ruleName, 'A')
  // 唯一成员必然对全部单元不可替代
  assert.equal(me.members[0].uniqueCells, me.declaredCells)
  assert.equal(me.members[0].coveredCells, me.declaredCells)
  // 代表报文可复现：首命中 A
  assert.equal(me.members[0].representative.matchedRuleName, 'A')
  assert.equal(me.members[0].representative.kind, 'shadowed')
})

test('最小解释集：共同覆盖时给出精确的最少规则集合，各成员均有不可替代单元', () => {
  const report = audit([
    rule({ name: 'lo1', cidr: '10.0.0.0/25' }),
    rule({ name: 'lo2', cidr: '10.0.0.128/25' }),
    rule({ name: 'cover', cidr: '10.0.0.0/24' }),
  ])
  const cover = report.entries[2]
  if (cover.kind !== 'valid') throw new Error('bad')
  const me = cover.minExplanation!
  assert.equal(me.skipped, false)
  assert.equal(me.members.length, 2)
  assert.deepEqual(
    me.members.map((m) => m.ruleName),
    ['lo1', 'lo2'],
  )
  assert.equal(me.coveredCells, cover.declaredCells)
  for (const m of me.members) {
    assert.ok(m.uniqueCells >= 1, '入选规则必须相对集合不可替代')
    assert.ok(m.coveredCells >= m.uniqueCells)
  }
})

test('最小解释集：同基数多个解时按规则序号数组字典序取唯一结果', () => {
  // 目标 T = /24 ANY（4 个单元：两个 /25 × TCP/UDP）
  // R1 /24 TCP、R3 /24 TCP 同掩码；R2 /24 UDP、R4 /24 UDP 同掩码
  // 可行二元组 {R1,R2}、{R1,R4}、{R2,R3}、{R3,R4}，字典序最小为 [R1,R2]
  const report = audit([
    rule({ name: 'R1', cidr: '10.0.0.0/24', portStart: '0', portEnd: '0', protocol: 'TCP' }),
    rule({ name: 'R2', cidr: '10.0.0.0/24', portStart: '0', portEnd: '0', protocol: 'UDP' }),
    rule({ name: 'R3', cidr: '10.0.0.0/24', portStart: '0', portEnd: '0', protocol: 'TCP' }),
    rule({ name: 'R4', cidr: '10.0.0.0/24', portStart: '0', portEnd: '0', protocol: 'UDP' }),
    rule({ name: 'T', cidr: '10.0.0.0/24', portStart: '0', portEnd: '0', protocol: 'ANY' }),
  ])
  const t = report.entries[4]
  if (t.kind !== 'valid') throw new Error('bad')
  assert.equal(t.status, 'fully-shadowed')
  const me = t.minExplanation!
  assert.equal(me.candidateCount, 4)
  assert.equal(me.members.length, 2)
  assert.deepEqual(
    me.members.map((m) => m.ruleName),
    ['R1', 'R2'],
  )
  // 单一 /24 IP 原子 × 单一端口原子 × {TCP,UDP} = 2 个声明单元
  assert.equal(me.declaredCells, 2)
  assert.equal(me.coveredCells, 2)
  // R1 独占 TCP 单元，R2 独占 UDP 单元
  assert.equal(me.members[0].uniqueCells, 1)
  assert.equal(me.members[0].coveredCells, 1)
  assert.equal(me.members[1].uniqueCells, 1)
})

test('最小解释集：成员不可替代单元的真实首命中者可在集合之外，代表报文按实标注', () => {
  // X 盖端口0（首命中 X）；M 声明端口0,1（0 被 X 夺走、1 归 M）；Y 盖端口2；T 盖 0,1,2
  // 可行最少解唯一：{M,Y}（{X,Y} 缺端口1）。M 相对集合的不可替代单元为 {0,1}，
  // 其中字典序最小的端口0真实首命中是 X（不在解释集中）——代表报文必须如实标注 X
  const mk = (name: string, s: number, e: number): RuleInput =>
    rule({ name, cidr: '10.0.0.0/24', portStart: String(s), portEnd: String(e), protocol: 'TCP' })
  const report = audit([mk('X', 0, 0), mk('M', 0, 1), mk('Y', 2, 2), mk('T', 0, 2)])
  const t = report.entries[3]
  if (t.kind !== 'valid') throw new Error('bad')
  const me = t.minExplanation!
  assert.equal(me.candidateCount, 3)
  assert.deepEqual(me.members.map((m) => m.ruleName), ['M', 'Y'])
  const m = me.members.find((x) => x.ruleName === 'M')!
  const y = me.members.find((x) => x.ruleName === 'Y')!
  assert.equal(m.coveredCells, 2)
  assert.equal(m.uniqueCells, 2)
  assert.equal(m.representative.srcPort, 0)
  assert.equal(m.representative.matchedRuleName, 'X') // 非 M 自身，而是真实首命中者
  assert.equal(y.uniqueCells, 1)
  assert.equal(y.representative.srcPort, 2)
  assert.equal(y.representative.matchedRuleName, 'Y')
  // 暴力复现代表报文：端口0的首命中确实是 X
  const { valid: normalized } = validateRules([
    mk('X', 0, 0), mk('M', 0, 1), mk('Y', 2, 2), mk('T', 0, 2),
  ])
  const hit = normalized.find(
    (r) =>
      ipv4ToInt(m.representative.srcIp) >= r.ipStart &&
      ipv4ToInt(m.representative.srcIp) <= r.ipEnd &&
      m.representative.srcPort >= r.portStart &&
      m.representative.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === m.representative.protocol),
  )
  assert.equal(hit!.name, 'X')
})

test('最小解释集：候选 18 条时精确求解；19 条时明确跳过、不给贪心结果', () => {
  const mk = (name: string, p: number): RuleInput =>
    rule({
      name,
      cidr: '10.0.0.0/24',
      portStart: String(p),
      portEnd: String(p),
      protocol: 'TCP',
    })

  // 18 个单端口前序规则 + 目标盖端口 0..17：候选恰好 18，精确解为全部 18 条
  const rules18 = Array.from({ length: 18 }, (_, i) => mk(`P${i}`, i))
  rules18.push(
    rule({ name: 'T18', cidr: '10.0.0.0/24', portStart: '0', portEnd: '17', protocol: 'TCP' }),
  )
  const rep18 = audit(rules18)
  const t18 = rep18.entries[18]
  if (t18.kind !== 'valid') throw new Error('bad')
  assert.equal(t18.status, 'fully-shadowed')
  const me18 = t18.minExplanation!
  assert.equal(me18.candidateCount, 18)
  assert.equal(me18.skipped, false)
  assert.equal(me18.members.length, 18)
  assert.equal(me18.coveredCells, 18)
  assert.deepEqual(
    me18.members.map((x) => x.ruleName),
    rules18.slice(0, 18).map((r) => r.name),
  )
  assert.ok(me18.members.every((x) => x.uniqueCells === 1))

  // 19 个候选：超过上限，必须 skipped 且不携带任何冒充最优的成员
  const rules19 = Array.from({ length: 19 }, (_, i) => mk(`Q${i}`, i))
  rules19.push(
    rule({ name: 'T19', cidr: '10.0.0.0/24', portStart: '0', portEnd: '18', protocol: 'TCP' }),
  )
  const rep19 = audit(rules19)
  const t19 = rep19.entries[19]
  if (t19.kind !== 'valid') throw new Error('bad')
  assert.equal(t19.status, 'fully-shadowed')
  const me19 = t19.minExplanation!
  assert.equal(me19.candidateCount, 19)
  assert.equal(me19.skipped, true)
  assert.equal(me19.members.length, 0)
  assert.equal(me19.coveredCells, 0)
})

test('最小解释集：仅完全遮蔽规则计算，其余状态恒为 null；非法/停用规则不是候选', () => {
  const report = audit([
    rule({ name: 'half', cidr: '10.0.0.0/25' }),
    rule({ name: 'partial', cidr: '10.0.0.0/24' }),
    rule({ name: 'dup', cidr: '10.0.0.0/25' }),
    rule({ name: 'off', cidr: '10.0.0.0/8', enabled: false }),
    rule({ name: 'bad', cidr: '10.0.0.5/24' }),
  ])
  for (const e of report.entries) {
    if (e.kind !== 'valid') continue
    if (e.status === 'fully-shadowed') assert.ok(e.minExplanation, `#${e.index + 1} 应有解释集`)
    else assert.equal(e.minExplanation, null)
  }
  // dup 与 half 同区域：half 单条即全覆盖；partial（/24）虽也是候选但不会入选
  const dup = report.entries[2]
  if (dup.kind !== 'valid') throw new Error('bad')
  assert.equal(dup.status, 'fully-shadowed')
  assert.equal(dup.minExplanation!.candidateCount, 2)
  assert.deepEqual(
    dup.minExplanation!.members.map((m) => m.ruleName),
    ['half'],
  )
})

console.log(`\n全部 ${passed} 项测试通过 ✔`)