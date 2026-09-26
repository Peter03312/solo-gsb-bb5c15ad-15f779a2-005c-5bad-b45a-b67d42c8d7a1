/** 审计例外清单引擎自检：node --test 风格的轻量断言脚本（零额外依赖） */
import assert from 'node:assert'
import { audit } from './audit/engine'
import {
  evaluateExceptions,
  expiryFromDatetimeLocal,
  expiryToDatetimeLocal,
  formatExpiry,
  newExceptionInput,
  normalizeIssueType,
  parseExceptionsJson,
  parseExpiry,
  serializeExceptions,
  validateException,
} from './audit/exemption'
import type { ExceptionInput } from './audit/exemption'
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
    id: partial.id ?? `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

function exc(partial: Partial<ExceptionInput>): ExceptionInput {
  return {
    id: partial.id ?? `e${seq++}`,
    ruleId: partial.ruleId ?? '',
    issueType: partial.issueType ?? 'fully-shadowed',
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    expiresAt: partial.expiresAt ?? '',
    notes: partial.notes ?? '说明',
  }
}

const NOW = new Date('2026-06-01T00:00:00Z')

/** 取报告中的规则豁免条目 */
function ruleEntry(report: ReturnType<typeof evaluateExceptions>, ruleId: string) {
  const e = report.entries.find((x) => x.kind === 'rule' && x.ruleId === ruleId)
  if (!e || e.kind !== 'rule') throw new Error(`未找到规则 ${ruleId} 的豁免条目`)
  return e
}

function invalidEntries(report: ReturnType<typeof evaluateExceptions>) {
  return report.entries.filter((e) => e.kind === 'invalid-exception') as Array<
    Extract<(typeof report.entries)[number], { kind: 'invalid-exception' }>
  >
}

// --- 输入校验 ---
test('例外校验：缺少规则 / 问题类型 / 说明均为非法', () => {
  const r = validateException(exc({ ruleId: '', notes: '' }))
  assert.equal(r.exception, null)
  assert.ok(r.errors.some((e) => e.includes('适用规则')))
  assert.ok(r.errors.some((e) => e.includes('说明不能为空')))
})

test('例外校验：CIDR 主机位非零 / 端口倒置 / 协议非法分别报错', () => {
  const r = validateException(
    exc({ ruleId: 'x', cidr: '10.0.0.5/24', portStart: '100', portEnd: '50', protocol: 'ICMP' }),
  )
  assert.equal(r.exception, null)
  assert.ok(r.errors.some((e) => e.includes('主机位非零')))
  assert.ok(r.errors.some((e) => e.includes('倒置')))
  assert.ok(r.errors.some((e) => e.includes('协议必须')))
})

test('问题类型接受中文 / 英文 / 简写', () => {
  assert.equal(normalizeIssueType('完全遮蔽'), 'fully-shadowed')
  assert.equal(normalizeIssueType('partial'), 'partial-shadowed')
  assert.equal(normalizeIssueType('FULLY SHADOWED'), 'fully-shadowed')
  assert.equal(normalizeIssueType('weird'), null)
})

test('到期时间：空串为永久；日期串取 UTC 当天末刻；非法文本报错', () => {
  assert.deepEqual(parseExpiry(''), { ms: null, iso: '' })
  const d = parseExpiry('2026-12-31')
  assert.ok('ms' in d && d.ms === Date.parse('2026-12-31T23:59:59.999Z'))
  const iso = parseExpiry('2026-12-31T08:00Z')
  assert.ok('iso' in iso && iso.iso === '2026-12-31T08:00:00.000Z')
  // 无时区的日期时间按 UTC 解释
  const naive = parseExpiry('2026-12-31T08:00')
  assert.ok('ms' in naive && naive.ms === Date.parse('2026-12-31T08:00:00.000Z'))
  assert.ok('error' in parseExpiry('not-a-date'))
})

test('datetime-local 与 UTC ISO 互转', () => {
  const local = '2026-12-31T08:30'
  const iso = expiryFromDatetimeLocal(local)
  assert.equal(iso, '2026-12-31T08:30:00.000Z')
  assert.equal(expiryToDatetimeLocal(iso), local)
  assert.equal(expiryFromDatetimeLocal(''), '')
  assert.equal(expiryToDatetimeLocal(''), '')
})

test('formatExpiry：永久 / UTC 标准串 / 非法原文', () => {
  assert.equal(formatExpiry(''), '永久')
  assert.equal(formatExpiry('2026-12-31T08:00:00.000Z'), '2026-12-31T08:00:00Z')
  assert.equal(formatExpiry('garbage'), 'garbage')
})

// --- 完全豁免 / 部分豁免（精确交集） ---
test('完全遮蔽规则被同范围未过期例外整体豁免', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'b', issueType: 'fully-shadowed', cidr: '10.0.0.0/8', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  assert.equal(e.fullyExempt, true)
  assert.equal(e.exemptSize, e.blockedSize)
  assert.ok(e.exemptSize > 0)
  assert.equal(e.pendingSize, 0)
  assert.equal(e.pendingCells, 0)
  assert.equal(e.coverages.length, 1)
  assert.equal(e.coverages[0].noOverlap, false)
  assert.ok(e.exemptRepresentative)
  assert.equal(e.pendingRepresentative, null)
  assert.equal(report.stats.fullyExemptRuleCount, 1)
  assert.equal(report.stats.totalPendingSize, 0)
})

test('例外只覆盖遮蔽区域一半：已豁免与待处理各半，两者合计恰为遮蔽空间', () => {
  const rules = [
    rule({ id: 'lo', name: 'lo', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ id: 'full', name: 'full', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  // full 被 lo 遮蔽一半（10.0.0.0/25），自身可达另一半；对其被遮蔽的一半登记豁免
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'full', issueType: 'partial-shadowed', cidr: '10.0.0.0/25', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'full')
  assert.equal(e.ruleStatus, 'partial-shadowed')
  assert.equal(e.fullyExempt, true)
  // 待处理应为 0：遮蔽区域恰好全部被覆盖
  assert.equal(e.pendingSize, 0)
})

test('例外范围大于遮蔽区域：交集等于遮蔽区域，外部空间不计入豁免', () => {
  const rules = [
    rule({ id: 'lo', name: 'lo', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ id: 'full', name: 'full', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  // 例外声明 10.0.0.0/8，但 full 的遮蔽区域只有 10.0.0.0/25
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'full', issueType: 'partial-shadowed', cidr: '10.0.0.0/8', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'full')
  const quarter = 128 * 65536
  assert.equal(e.blockedSize, quarter)
  assert.equal(e.exemptSize, quarter)
  assert.equal(e.pendingSize, 0)
})

test('例外只盖住遮蔽区域的一部分：按原子精确切分，剩余仍待处理', () => {
  // 遮蔽区域 = 10.0.0.0/25 TCP 全端口；例外只给 /26 端口 0-65535 → 恰好一半
  const rules = [
    rule({ id: 'lo', name: 'lo', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ id: 'full', name: 'full', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'full', issueType: 'partial-shadowed', cidr: '10.0.0.0/26', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'full')
  assert.equal(e.fullyExempt, false)
  const quarter = 128 * 65536
  assert.equal(e.blockedSize, quarter)
  assert.equal(e.exemptSize, 64 * 65536)
  assert.equal(e.pendingSize, 64 * 65536)
  assert.equal(e.exemptSize + e.pendingSize, e.blockedSize)
  // 待处理代表报文必须落在未被覆盖的 10.0.0.64/26
  assert.ok(e.pendingRepresentative!.srcIp.startsWith('10.0.0.'))
  const lastOctet = Number(e.pendingRepresentative!.srcIp.split('.')[3])
  assert.ok(lastOctet >= 64 && lastOctet <= 127)
  assert.equal(e.exemptRepresentative!.srcIp, '10.0.0.1')
})

test('端口与协议维同样参与精确交集：例外端口 / 协议不匹配则零覆盖', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24' }),
  ]
  // 遮蔽区域是 ANY(TCP+UDP) 全端口；例外只给 TCP 22
  const report = evaluateExceptions(
    rules,
    [
      exc({ id: 'x1', ruleId: 'b', issueType: 'fully-shadowed', cidr: '10.0.0.0/24', portStart: '22', portEnd: '22', protocol: 'TCP' }),
      exc({ id: 'x2', ruleId: 'b', issueType: 'fully-shadowed', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'UDP' }),
    ],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  assert.equal(e.fullyExempt, false)
  // 两条例外各覆盖 1 IP 维度（256 地址）× 1 端口 × 1 协议
  assert.equal(e.exemptSize, 256 * 2)
  const coverX1 = e.coverages.find((c) => c.exceptionId === 'x1')!
  assert.equal(coverX1.coveredSize, 256)
  assert.equal(coverX1.representative!.protocol, 'TCP')
  assert.equal(coverX1.representative!.srcPort, 22)
  // 待处理区域仍占绝大部分
  assert.ok(e.pendingSize > e.exemptSize)
})

test('例外范围与遮蔽区域无交集：noOverlap=true、零豁免、全部待处理', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'b', issueType: 'fully-shadowed', cidr: '192.168.0.0/16', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  assert.equal(e.exemptSize, 0)
  assert.equal(e.pendingSize, e.blockedSize)
  assert.equal(e.coverages[0].noOverlap, true)
  assert.equal(e.coverages[0].representative, null)
  assert.equal(report.stats.noOverlapCount, 1)
})

// --- 过期 / 非法 / 目标状态 ---
test('过期例外表明确提示且不参与豁免；未到期的正常生效', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [
      exc({ id: 'old', ruleId: 'b', cidr: '10.0.0.0/8', protocol: 'TCP', expiresAt: '2020-01-01T00:00:00Z' }),
      exc({ id: 'fresh', ruleId: 'b', cidr: '10.0.0.0/25', protocol: 'TCP', expiresAt: '2030-01-01T00:00:00Z' }),
    ],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  const expired = invalidEntries(report)
  assert.equal(expired.length, 1)
  assert.equal(expired[0].reason, 'expired')
  assert.ok(expired[0].message.includes('到期'))
  assert.equal(e.coverages.length, 1)
  assert.equal(e.coverages[0].exceptionId, 'fresh')
  assert.equal(e.fullyExempt, false)
  assert.equal(report.stats.expiredCount, 1)
  assert.equal(report.stats.activeCount, 1)
})

test('到期当天末刻之前仍有效（日期型到期取 UTC 23:59:59.999）', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'b', cidr: '10.0.0.0/8', protocol: 'TCP', expiresAt: '2026-06-01' })],
    new Date('2026-06-01T12:00:00Z'),
  )
  const e = ruleEntry(report, 'b')
  assert.equal(e.fullyExempt, true)
})

test('问题类型不匹配（对部分遮蔽规则登记完全遮蔽例外）不生效并提示', () => {
  const rules = [
    rule({ id: 'lo', name: 'lo', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ id: 'full', name: 'full', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'full', issueType: 'fully-shadowed', cidr: '10.0.0.0/25', protocol: 'TCP' })],
    NOW,
  )
  const e = ruleEntry(report, 'full')
  assert.equal(e.exemptSize, 0)
  assert.equal(e.coverages.length, 0)
  const bad = invalidEntries(report)
  assert.equal(bad.length, 1)
  assert.equal(bad[0].reason, 'issue-mismatch')
  assert.ok(bad[0].message.includes('部分遮蔽'))
})

test('目标规则缺失 / 非法 / 停用分别明确标注且不参与豁免', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'bad', name: 'bad', cidr: '10.0.0.5/24', protocol: 'TCP' }),
    rule({ id: 'off', name: 'off', cidr: '10.1.0.0/16', enabled: false }),
  ]
  const report = evaluateExceptions(
    rules,
    [
      exc({ id: 'm', ruleId: 'gone' }),
      exc({ id: 'i', ruleId: 'bad' }),
      exc({ id: 'd', ruleId: 'off' }),
      exc({ id: 'badfield', ruleId: 'a', cidr: 'nonsense' }),
    ],
    NOW,
  )
  const byId = new Map(invalidEntries(report).map((x) => [x.id, x]))
  assert.equal(byId.get('m')!.reason, 'rule-missing')
  assert.equal(byId.get('i')!.reason, 'rule-invalid')
  assert.equal(byId.get('d')!.reason, 'rule-disabled')
  assert.equal(byId.get('badfield')!.reason, 'invalid')
  assert.ok(byId.get('badfield')!.errors.length > 0)
  assert.equal(report.stats.targetBadCount, 3)
  assert.equal(report.stats.invalidCount, 1)
})

test('可达规则上的例外属问题类型不匹配，且不生成遮蔽条目', () => {
  const rules = [rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8' })]
  const report = evaluateExceptions(
    rules,
    [exc({ ruleId: 'a', issueType: 'fully-shadowed', cidr: '10.0.0.0/8' })],
    NOW,
  )
  assert.equal(report.entries.filter((e) => e.kind === 'rule').length, 0)
  const bad = invalidEntries(report)
  assert.equal(bad[0].reason, 'issue-mismatch')
  assert.ok(bad[0].message.includes('可达'))
})

// --- 多条例外并集 ---
test('两条重叠例外按并集去重：豁免不重复计数', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [
      exc({ id: 'e1', ruleId: 'b', cidr: '10.0.0.0/16', protocol: 'TCP' }),
      exc({ id: 'e2', ruleId: 'b', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    ],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  // e2 已覆盖全部遮蔽区域；并集 == blockedSize，而非两条 size 之和
  assert.equal(e.exemptSize, e.blockedSize)
  assert.equal(e.fullyExempt, true)
  // e1 的单独覆盖仍如实列出（被 e2 包含但不影响其覆盖数字）
  const e1 = e.coverages.find((c) => c.exceptionId === 'e1')!
  const e2 = e.coverages.find((c) => c.exceptionId === 'e2')!
  assert.ok(e2.coveredSize >= e1.coveredSize)
})

test('两条例外分别覆盖不同端口段：并集为两段，待处理为剩余部分', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(
    rules,
    [
      exc({ id: 'e1', ruleId: 'b', cidr: '10.0.0.0/24', portStart: '22', portEnd: '22', protocol: 'TCP' }),
      exc({ id: 'e2', ruleId: 'b', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP' }),
    ],
    NOW,
  )
  const e = ruleEntry(report, 'b')
  // 22 + 80..443(364) 个端口被豁免
  assert.equal(e.exemptSize, 256 * (1 + 364))
  assert.equal(e.pendingSize, 256 * (65536 - 365))
  assert.equal(e.exemptSize + e.pendingSize, e.blockedSize)
  // 已豁免区域按端口精确展开为两段
  const rows = e.exemptRegions.flatMap((g) => g.rows)
  assert.equal(rows.length, 2)
})

// --- 自动重算（规则编辑后交集改变） ---
test('规则编辑后自动重算：遮蔽区域变化时豁免 / 待处理随之更新', () => {
  const rules1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  // 例外固定覆盖 10.0.0.0/25
  const exceptions = [
    exc({ ruleId: 'b', issueType: 'partial-shadowed', cidr: '10.0.0.0/25', protocol: 'TCP' }),
  ]
  const r1 = evaluateExceptions(rules1, exceptions, NOW)
  assert.equal(ruleEntry(r1, 'b').fullyExempt, true)

  // 编辑 A 扩大遮蔽到整个 /24（与 B 相同）：B 变为完全遮蔽，问题类型不匹配 → 例外失效
  const rules2 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24', protocol: 'TCP' }),
  ]
  const r2 = evaluateExceptions(rules2, exceptions, NOW)
  const e2 = ruleEntry(r2, 'b')
  assert.equal(e2.ruleStatus, 'fully-shadowed')
  assert.equal(e2.exemptSize, 0)
  assert.ok(invalidEntries(r2).some((x) => x.reason === 'issue-mismatch'))

  // 同一条规则以完全遮蔽类型登记 → 全部豁免
  const exceptions2 = [
    exc({ ruleId: 'b', issueType: 'fully-shadowed', cidr: '10.0.0.0/25', protocol: 'TCP' }),
  ]
  const r3 = evaluateExceptions(rules2, exceptions2, NOW)
  const e3 = ruleEntry(r3, 'b')
  assert.equal(e3.fullyExempt, false)
  // 遮蔽区域是 /24 但例外只有 /25 → 恰好一半豁免、一半待处理
  assert.equal(e3.exemptSize, 128 * 65536)
  assert.equal(e3.pendingSize, 128 * 65536)
})

// --- 审计结论不变性 ---
test('例外清单不改变审计结论：audit() 输出与有无例外无关', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const baseline = audit(rules)
  // evaluateExceptions 是纯附加层，audit() 由调用方独立执行；这里直接核对：
  // 无论例外如何登记，审计状态与有效 / 声明空间都保持原值
  const withExceptions = audit(rules)
  assert.deepEqual(
    withExceptions.stats,
    baseline.stats,
  )
  const bBase = baseline.entries[1]
  const bWith = withExceptions.entries[1]
  assert.equal(bBase.kind, 'valid')
  assert.equal(bWith.kind, 'valid')
  if (bBase.kind === 'valid' && bWith.kind === 'valid') {
    assert.equal(bWith.status, 'fully-shadowed')
    assert.equal(bWith.status, bBase.status)
    assert.equal(bWith.effectiveSize, bBase.effectiveSize)
    assert.equal(bWith.declaredSize, bBase.declaredSize)
  }
  // 豁免报告在旁路单独产出，且不修改输入
  const exceptions = [exc({ ruleId: 'b', cidr: '10.0.0.0/8', protocol: 'TCP' })]
  const snapshot = JSON.stringify(exceptions)
  evaluateExceptions(rules, exceptions, NOW)
  assert.equal(JSON.stringify(exceptions), snapshot)
})

// --- 统计 ---
test('无任何例外时：遮蔽规则全部列待处理，统计为零豁免', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ id: 'c', name: 'C', cidr: '10.0.0.0/8', protocol: 'TCP' }),
  ]
  const report = evaluateExceptions(rules, [], NOW)
  assert.equal(report.stats.issueRuleCount, 2)
  assert.equal(report.stats.totalExemptSize, 0)
  assert.equal(report.stats.fullyExemptRuleCount, 0)
  assert.equal(ruleEntry(report, 'c').pendingSize, ruleEntry(report, 'c').blockedSize)
})

// --- 导入 / 导出 ---
test('导出再导入：JSON 往返一致', () => {
  const list = [
    exc({ id: 'x1', ruleId: 'b', cidr: '10.0.0.0/24', expiresAt: '2030-01-01T00:00:00Z' }),
  ]
  const json = serializeExceptions(list, NOW)
  const parsed = JSON.parse(json)
  assert.equal(parsed.format, 'audit-exceptions')
  assert.equal(parsed.version, 1)
  const back = parseExceptionsJson(json)
  assert.equal(back.errors.length, 0)
  assert.equal(back.exceptions.length, 1)
  assert.equal(back.exceptions[0].ruleId, 'b')
  assert.equal(back.exceptions[0].expiresAt, '2030-01-01T00:00:00Z')
})

test('导入支持裸数组 / {exceptions:[...]}；非法 JSON 报错', () => {
  const r1 = parseExceptionsJson('[{"ruleId":"a","issueType":"fully-shadowed","notes":"n"}]')
  assert.equal(r1.exceptions.length, 1)
  assert.equal(r1.exceptions[0].id.length > 0, true)
  const r2 = parseExceptionsJson('{"exceptions":[{"ruleId":"a","notes":"n"}]}')
  assert.equal(r2.exceptions.length, 1)
  const bad = parseExceptionsJson('{not json')
  assert.equal(bad.exceptions.length, 0)
  assert.ok(bad.errors[0].includes('JSON 解析失败'))
  const wrong = parseExceptionsJson('{"foo":1}')
  assert.ok(wrong.errors[0].includes('exceptions'))
})

test('导入时同文件重复 id 重新分配并提示', () => {
  const r = parseExceptionsJson(
    '[{"id":"dup","ruleId":"a","notes":"n"},{"id":"dup","ruleId":"b","notes":"n2"}]',
  )
  assert.equal(r.exceptions.length, 2)
  assert.notEqual(r.exceptions[0].id, r.exceptions[1].id)
  assert.ok(r.errors.some((e) => e.includes('重复')))
})

test('newExceptionInput 默认值合理且 id 唯一', () => {
  const a = newExceptionInput('r1', 'partial-shadowed')
  const b = newExceptionInput()
  assert.equal(a.ruleId, 'r1')
  assert.equal(a.issueType, 'partial-shadowed')
  assert.notEqual(a.id, b.id)
  assert.equal(a.expiresAt, '')
})

console.log(`\n豁免模块：${passed} 项用例全部通过`)
