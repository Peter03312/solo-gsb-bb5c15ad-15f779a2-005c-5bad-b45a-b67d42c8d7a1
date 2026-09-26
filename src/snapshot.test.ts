/**
 * 审计快照对比引擎自检：
 * 快照深拷贝、合并原子空间上的四类逐单元重放（动作未变 / 动作改变 /
 * 命中↔未命中）、同动作易主分组、ANY 协议拆分、精确区域行合计、
 * 代表报文可复现、非法 / 停用排除与统计、localStorage 不可用降级。
 */
import assert from 'node:assert'
import { compareSnapshots, createSnapshot, loadSnapshots, persistSnapshots, snapshotRuleStats } from './audit/snapshot'
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
function rule(partial: Partial<RuleInput> & { id?: string }): RuleInput {
  return {
    id: partial.id ?? `t${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

/** 暴力首命中：在给定合法规则数组上判定一个具体报文的首命中规则 */
function bruteHit(
  rules: RuleInput[],
  ipNum: number,
  port: number,
  protocol: 'TCP' | 'UDP',
) {
  const { valid } = validateRules(rules)
  return valid
    .filter((r) => r.enabled)
    .find(
      (r) =>
        ipNum >= r.ipStart &&
        ipNum <= r.ipEnd &&
        port >= r.portStart &&
        port <= r.portEnd &&
        (r.protocol === 'ANY' || r.protocol === protocol),
    )
}

/** 对每个分组 / 类别校验：精确区域各行大小合计 == 自身 size */
function assertRegionTotals(groups: { size: number; regions: Array<{ size: number }> }[]) {
  for (const g of groups) {
    assert.equal(
      g.regions.reduce((s, r) => s + r.size, 0),
      g.size,
    )
  }
}

test('完全相同的两个快照：全部单元动作未变、无易主、无差异', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ id: 'b', name: 'B', cidr: '0.0.0.0/0', action: 'deny' }),
  ]
  const s1 = createSnapshot('v1', rules, new Date('2026-01-01T00:00:00Z'))
  const s2 = createSnapshot('v2', rules, new Date('2026-02-01T00:00:00Z'))
  const diff = compareSnapshots(s1, s2)
  // 10/8 两协议归 A；其余归 B；所有报文都被覆盖
  assert.equal(diff.categories.unchanged.size, 2 ** 32 * 65536 * 2)
  assert.equal(diff.categories['action-changed'].cells, 0)
  assert.equal(diff.categories['became-unmatched'].cells, 0)
  assert.equal(diff.categories['became-matched'].cells, 0)
  assert.equal(diff.hasActionDifference, false)
  assert.equal(diff.hasReassignment, false)
  assert.equal(diff.categories.unchanged.groups.length, 0)
})

test('同一规则动作翻转：动作改变单元、区域与前后规则引用精确', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'deny' }),
  ])
  const diff = compareSnapshots(s1, s2)
  const c = diff.categories['action-changed']
  assert.equal(c.size, 256)
  assert.equal(c.cells, 1)
  assert.equal(diff.comparedSize, 256)
  assert.equal(diff.hasActionDifference, true)
  assert.deepEqual(c.regions[0].rows, [
    { portStart: 80, portEnd: 80, cidrs: ['10.0.0.0/24'], size: 256 },
  ])
  assert.equal(c.groups.length, 1)
  const g = c.groups[0]
  assert.equal(g.before?.name, 'A')
  assert.equal(g.before?.action, 'allow')
  assert.equal(g.after?.action, 'deny')
  assert.equal(g.after?.index, 0)
  assert.equal(g.size, 256)
  // 代表报文确定且可复现：/24 第 2 个地址、段首端口
  assert.deepEqual(g.packet, { srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP' })
  assert.deepEqual(c.examples, [{ srcIp: '10.0.0.1', srcPort: 80, protocol: 'TCP' }])
})

test('删除唯一覆盖规则：由命中变为未命中，精确区域与代表报文指向旧规则', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '192.168.1.0/24', portStart: '22', portEnd: '22', protocol: 'UDP', action: 'deny' }),
  ])
  const s2 = createSnapshot('v2', [])
  const diff = compareSnapshots(s1, s2)
  const c = diff.categories['became-unmatched']
  assert.equal(c.size, 256)
  assert.equal(diff.categories.unchanged.size, 0)
  assert.equal(c.groups.length, 1)
  const g = c.groups[0]
  assert.equal(g.before?.name, 'A')
  assert.equal(g.after, null)
  assert.deepEqual(g.regions[0].rows, [
    { portStart: 22, portEnd: 22, cidrs: ['192.168.1.0/24'], size: 256 },
  ])
  assert.deepEqual(g.packet, { srcIp: '192.168.1.1', srcPort: 22, protocol: 'UDP' })
})

test('新增规则覆盖空白空间：由未命中变为命中，基准侧引用为 null', () => {
  const s1 = createSnapshot('v1', [])
  const s2 = createSnapshot('v2', [
    rule({ id: 'b', name: 'B', cidr: '172.16.0.0/16', portStart: '443', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ])
  const diff = compareSnapshots(s1, s2)
  const c = diff.categories['became-matched']
  assert.equal(c.size, 65536)
  assert.equal(c.groups.length, 1)
  const g = c.groups[0]
  assert.equal(g.before, null)
  assert.equal(g.after?.name, 'B')
  assert.equal(g.packet.srcPort, 443)
  assert.equal(g.packet.protocol, 'TCP')
})

test('合并原子空间被对侧 /25 边界切开：同动作易主归入动作未变分组，异动作一半精确标出', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 't1', name: 'T1', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 't2', name: 'T2', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ])
  const diff = compareSnapshots(s1, s2)
  const half = 128 * 65536
  assert.equal(diff.categories['action-changed'].size, half)
  assert.deepEqual(
    diff.categories['action-changed'].groups[0].regions[0].rows,
    [{ portStart: 0, portEnd: 65535, cidrs: ['10.0.0.128/25'], size: half }],
  )
  // 低 /25：A(allow) → T1(allow)，动作未变但易主
  const unchanged = diff.categories.unchanged
  assert.equal(unchanged.size, half)
  assert.equal(diff.hasReassignment, true)
  assert.equal(unchanged.groups.length, 1)
  const g = unchanged.groups[0]
  assert.equal(g.before?.name, 'A')
  assert.equal(g.after?.name, 'T1')
  assert.equal(g.size, half)
  assert.deepEqual(g.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.0/25'], size: half },
  ])
})

test('仅新增同动作前缀规则：无动作级差异，但同动作易主区域精确', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '0.0.0.0/0', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ id: 'a', name: 'A', cidr: '0.0.0.0/0', action: 'allow' }),
  ])
  const diff = compareSnapshots(s1, s2)
  assert.equal(diff.hasActionDifference, false)
  assert.equal(diff.hasReassignment, true)
  // 10/8 × 全端口 × TCP/UDP 易主；其余 A→A 不建组
  const moved = diff.categories.unchanged.groups
  assert.equal(moved.length, 1)
  assert.equal(moved[0].before?.name, 'A')
  assert.equal(moved[0].after?.name, 'B')
  assert.equal(moved[0].size, 2 ** 24 * 65536 * 2)
  assert.equal(diff.categories.unchanged.size, 2 ** 32 * 65536 * 2)
})

test('ANY 收窄为 TCP：UDP 流量由命中变为未命中，TCP 动作未变', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
  ])
  const diff = compareSnapshots(s1, s2)
  assert.equal(diff.categories['became-unmatched'].size, 256 * 65536)
  assert.equal(diff.categories['became-unmatched'].regions[0].protocol, 'UDP')
  assert.equal(diff.categories.unchanged.size, 256 * 65536)
  assert.equal(diff.categories.unchanged.regions[0].protocol, 'TCP')
})

test('端口区间收窄：未命中类别展开为两段连续端口行', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ])
  const diff = compareSnapshots(s1, s2)
  const c = diff.categories['became-unmatched']
  assert.equal(c.size, 256 * (65536 - 364))
  // 合并端口原子：[0,79] / [80,443] / [444,65535]，未命中是首尾两段
  assert.deepEqual(
    c.regions[0].rows.map((r) => [r.portStart, r.portEnd]),
    [
      [0, 79],
      [444, 65535],
    ],
  )
  // 单一未命中分组（同一旧规则 → null），其区域合计等于类别大小
  assert.equal(c.groups.length, 1)
  assert.equal(c.groups[0].size, c.size)
})

test('快照深拷贝：保存后编辑规则不改变快照与既有对比结论', () => {
  const rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', action: 'allow' }),
  ]
  const snap = createSnapshot('v1', rules)
  rules[0].action = 'deny'
  rules.push(rule({ name: 'new', cidr: '0.0.0.0/0', action: 'deny' }))
  assert.equal(snap.rules.length, 1)
  assert.equal(snap.rules[0].action, 'allow')
  const snap2 = createSnapshot('v2', rules)
  const diff = compareSnapshots(snap, snap2)
  // 10/8 allow→deny 动作改变；10/8 之外由未命中变为命中 deny
  assert.equal(diff.categories['action-changed'].size, 2 ** 24 * 65536 * 2)
  assert.equal(
    diff.categories['became-matched'].size,
    (2 ** 32 - 2 ** 24) * 65536 * 2,
  )
})

test('同一对比重复运行结果完全确定（含分组与代表报文）', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ id: 'b', name: 'B', cidr: '0.0.0.0/0', action: 'deny' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'b', name: 'B', cidr: '0.0.0.0/0', action: 'deny' }),
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', action: 'allow' }),
  ])
  const fixed = new Date('2026-03-01T00:00:00Z')
  const d1 = compareSnapshots(s1, s2, fixed)
  const d2 = compareSnapshots(s1, s2, fixed)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(d1)), JSON.parse(JSON.stringify(d2)))
})

test('非法与停用规则不参与重放，但计入快照构成统计', () => {
  const snap = createSnapshot('v1', [
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.0/8', action: 'allow', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', action: 'allow' }),
  ])
  assert.deepEqual(snapshotRuleStats(snap), { total: 3, active: 1, invalid: 1, disabled: 1 })
  const empty = createSnapshot('v2', [])
  const diff = compareSnapshots(empty, snap)
  // 仅合法启用的 10/8 规则产生「由未命中变为命中」
  assert.equal(diff.categories['became-matched'].size, 2 ** 24 * 65536 * 2)
  assert.equal(diff.targetStats.invalid, 1)
  assert.equal(diff.targetStats.disabled, 1)
})

test('各类别与各分组的精确区域行合计与单元级大小一致', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'b', name: 'B', cidr: '192.168.0.0/16', portStart: '0', portEnd: '1024', action: 'deny' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'a2', name: 'A2', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'b', name: 'B', cidr: '192.168.0.0/16', portStart: '0', portEnd: '512', action: 'deny' }),
    rule({ id: 'c', name: 'C', cidr: '172.16.0.0/12', action: 'log' }),
  ])
  const diff = compareSnapshots(s1, s2)
  let sum = 0
  for (const category of [
    diff.categories.unchanged,
    diff.categories['action-changed'],
    diff.categories['became-unmatched'],
    diff.categories['became-matched'],
  ]) {
    assert.equal(
      category.regions.reduce((s, r) => s + r.size, 0),
      category.size,
    )
    assertRegionTotals(category.groups)
    sum += category.size
  }
  assert.equal(sum, diff.comparedSize)
})

test('代表报文在两个快照上暴力重放，与分类的前后动作 / 未命中一致', () => {
  const s1rules = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const s2rules = [
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/24', portStart: '443', portEnd: '8080', protocol: 'TCP', action: 'deny' }),
  ]
  const diff = compareSnapshots(createSnapshot('v1', s1rules), createSnapshot('v2', s2rules))
  for (const categoryName of [
    'action-changed',
    'became-unmatched',
    'became-matched',
  ] as const) {
    const category = diff.categories[categoryName]
    for (const g of category.groups) {
      const p = g.packet
      const ipNum = ipv4ToInt(p.srcIp)
      const before = bruteHit(s1rules, ipNum, p.srcPort, p.protocol)
      const after = bruteHit(s2rules, ipNum, p.srcPort, p.protocol)
      assert.equal(before?.name, g.before?.name)
      assert.equal(after?.name, g.after?.name)
      assert.equal(before?.action ?? null, g.before?.action ?? null)
      assert.equal(after?.action ?? null, g.after?.action ?? null)
      // 用例中无完全同动作的类别
      assert.notEqual(before?.action, after?.action)
    }
  }
  // 80-442 变为未命中；443 动作改变 allow→deny；444-8080 由未命中变为命中
  assert.ok(diff.categories['became-unmatched'].size > 0)
  assert.ok(diff.categories['action-changed'].size > 0)
  assert.ok(diff.categories['became-matched'].size > 0)
})

test('两个快照均未覆盖的单元不参与对比（comparedSize 不含空白空间）', () => {
  const s1 = createSnapshot('v1', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
  ])
  const s2 = createSnapshot('v2', [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' }),
  ])
  const diff = compareSnapshots(s1, s2)
  // 只有 /24 × 全端口 × TCP 进入对比，其余 4G 空间双方都未覆盖
  assert.equal(diff.comparedSize, 256 * 65536)
  assert.equal(diff.categories['action-changed'].size, 256 * 65536)
})

test('localStorage 不可用时：读取返回空列表、写入不抛错（仅内存降级）', () => {
  assert.doesNotThrow(() => persistSnapshots([]))
  assert.deepEqual(loadSnapshots(), [])
})

console.log(`\n审计快照对比 ${passed} 项测试通过 ✔`)
