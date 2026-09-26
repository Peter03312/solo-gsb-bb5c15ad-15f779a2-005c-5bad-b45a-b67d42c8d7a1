/**
 * 双级串联策略引擎自检：
 * 放行动作列表解析、目标 / JSON / 动作列表输入错误阻止分析、
 * 两阶段串联重放（首命中动作在放行列表内才继续、未命中也阻断、
 * 一阶段阻断不进入二阶段、报文不改写）、三类精确划分、ANY 分协议统计、
 * 非法 / 停用规则两阶段排除与计数、目标与双方边界合并切分、
 * 轨迹分组与代表报文可暴力复现、精确区域行合计、确定性。
 */
import assert from 'node:assert'
import {
  analyzeTandem,
  evaluateTandem,
  parseAllowActions,
  validateTandemTarget,
} from './audit/tandem'
import type { TandemFormInput } from './audit/tandem'
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

const TARGET = {
  cidr: '10.0.0.0/8',
  portStart: '0',
  portEnd: '65535',
  protocol: 'ANY',
}

function form(partial: Partial<TandemFormInput> = {}): TandemFormInput {
  return {
    stage2Json: partial.stage2Json ?? '[]',
    allow1Text: partial.allow1Text ?? 'allow',
    allow2Text: partial.allow2Text ?? 'allow',
    target: partial.target ?? TARGET,
  }
}

function json(rules: Array<Partial<RuleInput>>): string {
  return JSON.stringify(rules.map((r) => rule(r)))
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

// ---------------------------------------------------------------------------
// 输入校验
// ---------------------------------------------------------------------------

test('放行动作列表：多种分隔符、去重、保持顺序、精确匹配', () => {
  assert.deepEqual(parseAllowActions('allow, permit；pass、accept allow'), [
    'allow',
    'permit',
    'pass',
    'accept',
  ])
  assert.deepEqual(parseAllowActions('  '), [])
  assert.deepEqual(parseAllowActions('Allow'), ['Allow'])
})

test('目标 CIDR / 端口 / 协议错误阻止分析', () => {
  let out = evaluateTandem(
    [rule({ name: 'A' })],
    form({ target: { ...TARGET, cidr: '10.0.0.5/8' } }),
  )
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('主机位非零')))

  out = evaluateTandem(
    [rule({ name: 'A' })],
    form({ target: { ...TARGET, portStart: '100', portEnd: '99' } }),
  )
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('倒置')))

  out = evaluateTandem(
    [rule({ name: 'A' })],
    form({ target: { ...TARGET, protocol: 'ICMP' } }),
  )
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('协议必须')))

  assert.equal(validateTandemTarget({ ...TARGET, cidr: '' }).errors.length > 0, true)
})

test('放行动作列表为空阻止分析（两阶段分别校验）', () => {
  let out = evaluateTandem([rule({})], form({ allow1Text: '  ' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('第一阶段放行动作列表')))

  out = evaluateTandem([rule({})], form({ allow2Text: '' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('第二阶段放行动作列表')))
})

test('第二阶段 JSON 为空或结构错误阻止分析（非法规则本身不阻止）', () => {
  let out = evaluateTandem([rule({})], form({ stage2Json: '' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('第二阶段规则 JSON 不能为空')))

  out = evaluateTandem([rule({})], form({ stage2Json: 'not json' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('第二阶段 JSON')))

  out = evaluateTandem([rule({})], form({ stage2Json: '42' }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.length > 0)

  out = evaluateTandem([rule({})], form({ stage2Json: '[{"cidr":"10/8"}]' }))
  assert.equal(out.ok, true) // 规则级非法：保留并按既有语义排除，不阻止分析

  out = evaluateTandem([rule({})], form({ stage2Json: '[1, 2]' }))
  assert.equal(out.ok, false) // 条目非对象：JSON 结构错误
})

test('第二阶段空数组合法：进入二阶段的报文因未命中全部阻断', () => {
  const out = evaluateTandem(
    [rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })],
    form({ stage2Json: '[]' }),
  )
  assert.equal(out.ok, true)
  if (!out.ok) throw new Error('应通过校验')
  const r = out.result
  assert.equal(r.stage2.active, 0)
  assert.equal(r.categories['blocked-stage2'].size, r.totalSize)
  assert.equal(r.categories.pass.size, 0)
  assert.equal(r.categories['blocked-stage1'].size, 0)
})

// ---------------------------------------------------------------------------
// 串联语义
// ---------------------------------------------------------------------------

test('两阶段全部放行：目标全部最终通过，轨迹为 一阶段规则 → 二阶段规则', () => {
  const stage1 = [rule({ id: 'a', name: 'A', cidr: '10.0.0.0/8', action: 'allow' })]
  const out = evaluateTandem(stage1, form({ stage2Json: json([{ name: 'B', cidr: '10.0.0.0/8' }]) }))
  assert.equal(out.ok, true)
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const total = 2 ** 24 * 65536 * 2
  assert.equal(r.totalSize, total)
  assert.equal(r.categories.pass.size, total)
  assert.equal(r.categories['blocked-stage1'].size, 0)
  assert.equal(r.categories['blocked-stage2'].size, 0)
  assert.equal(r.categories.pass.groups.length, 1)
  const g = r.categories.pass.groups[0]
  assert.equal(g.stage1?.name, 'A')
  assert.equal(g.stage2?.name, 'B')
  // 代表报文：块内第 2 个地址、段首端口；TCP / UDP 各一
  assert.deepEqual(r.categories.pass.examples, [
    { srcIp: '10.0.0.1', srcPort: 0, protocol: 'TCP', stage1: g.stage1, enteredStage2: true, stage2: g.stage2 },
    { srcIp: '10.0.0.1', srcPort: 0, protocol: 'UDP', stage1: g.stage1, enteredStage2: true, stage2: g.stage2 },
  ])
})

test('第一阶段未命中：第一阶段阻断且不进入第二阶段（即使二阶段会放行）', () => {
  const stage1 = [rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', action: 'allow' })]
  const out = evaluateTandem(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { ...TARGET, cidr: '10.0.0.0/24' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const half = 128 * 65536 * 2
  assert.equal(r.categories.pass.size, half)
  assert.equal(r.categories['blocked-stage1'].size, half)
  assert.equal(r.categories['blocked-stage2'].size, 0)
  const g = r.categories['blocked-stage1'].groups[0]
  assert.equal(g.stage1, null)
  assert.equal(g.enteredStage2, false)
  assert.equal(g.stage2, null)
})

test('第一阶段首命中动作不在放行列表：第一阶段阻断，不进入第二阶段', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' })]
  const out = evaluateTandem(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage1'].size, 256 * 65536)
  const g = r.categories['blocked-stage1'].groups[0]
  assert.equal(g.stage1?.action, 'deny')
  assert.equal(g.enteredStage2, false)
})

test('第二阶段未命中：第二阶段阻断，轨迹为 一阶段命中 → 二阶段未命中', () => {
  const stage1 = [rule({ name: 'A', cidr: '0.0.0.0/0', action: 'allow' })]
  const out = evaluateTandem(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '10.0.0.0/25' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const half = 128 * 65536
  assert.equal(r.categories.pass.size, half)
  assert.equal(r.categories['blocked-stage2'].size, half)
  const g = r.categories['blocked-stage2'].groups[0]
  assert.equal(g.stage1?.name, 'A')
  assert.equal(g.enteredStage2, true)
  assert.equal(g.stage2, null)
})

test('第二阶段首命中动作不在放行列表：第二阶段阻断', () => {
  const stage1 = [rule({ name: 'A', cidr: '0.0.0.0/0', action: 'allow' })]
  const out = evaluateTandem(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '10.0.0.0/24', action: 'drop' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage2'].size, 256 * 65536)
  assert.equal(r.categories['blocked-stage2'].groups[0].stage2?.action, 'drop')
})

test('多动作放行列表（精确匹配、大小写敏感）', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'permit' }),
  ]
  const okOut = evaluateTandem(
    stage1,
    form({
      allow1Text: 'allow, permit',
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  assert.equal(okOut.ok, true)
  if (!okOut.ok) throw new Error(JSON.stringify(okOut.errors))
  assert.equal(okOut.result.categories.pass.size, 256 * 65536)

  const caseOut = evaluateTandem(
    stage1,
    form({
      allow1Text: 'Permit',
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  if (!caseOut.ok) throw new Error(JSON.stringify(caseOut.errors))
  assert.equal(caseOut.result.categories['blocked-stage1'].size, 256 * 65536)
})

test('ANY 目标分协议统计：TCP 通过、UDP 第一阶段未命中阻断', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
  ]
  const out = evaluateTandem(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const tcp = out.result.perProtocol.find((p) => p.protocol === 'TCP')!
  const udp = out.result.perProtocol.find((p) => p.protocol === 'UDP')!
  assert.equal(tcp.passSize, 256 * 65536)
  assert.equal(udp.blockedStage1Size, 256 * 65536)
  assert.equal(udp.passSize, 0)
})

test('非法与停用规则在两个阶段均排除并计数', () => {
  const stage1 = [
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.0/8', action: 'deny', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', action: 'allow' }),
  ]
  const stage2 = [
    { id: 'ok2', name: 'OK2', cidr: '10.0.0.0/8', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'allow' },
    { id: 'off2', name: 'OFF2', cidr: '0.0.0.0/0', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'deny', enabled: false },
    { id: 'bad2', name: 'BAD2', cidr: '10.0.0.5/24', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'allow' },
  ]
  const out = evaluateTandem(stage1, form({ stage2Json: JSON.stringify(stage2) }))
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.deepEqual(r.stage1, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.deepEqual(r.stage2, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.equal(r.categories.pass.size, 2 ** 24 * 65536 * 2)
})

test('目标边界落在规则原子内部也被精确切开（精确到目标一半）', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const stage2 = [rule({ name: 'B', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' })]
  const target = {
    cidr: '10.0.0.128/25',
    portStart: '0',
    portEnd: '65535',
    protocol: 'TCP' as const,
  }
  const { target: normalized, errors } = validateTandemTarget(target)
  assert.equal(errors.length, 0)
  const r = analyzeTandem(stage1, stage2, ['allow'], ['allow'], normalized!)
  assert.equal(r.totalSize, 128 * 65536)
  assert.equal(r.categories['blocked-stage2'].size, 128 * 65536)
  assert.deepEqual(r.categories['blocked-stage2'].regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.128/25'], size: 128 * 65536 },
  ])
})

test('三分类精确划分：三类与各轨迹分组的区域行合计均与单元级大小一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ]
  const stage2 = [
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/26', protocol: 'TCP', action: 'allow' }),
  ]
  const target = {
    cidr: '10.0.0.0/24',
    portStart: '80',
    portEnd: '443',
    protocol: 'TCP' as const,
  }
  const { target: normalized, errors } = validateTandemTarget(target)
  assert.equal(errors.length, 0)
  const r = analyzeTandem(stage1, stage2, ['allow'], ['allow'], normalized!)
  const sum =
    r.categories.pass.size +
    r.categories['blocked-stage1'].size +
    r.categories['blocked-stage2'].size
  assert.equal(sum, r.totalSize)
  // 10.0.0.0/26 通过；10.0.0.64/26 第一阶段放行但第二阶段未命中；10.0.0.128/25 第一阶段 deny
  assert.equal(r.categories.pass.size, 64 * 364)
  assert.equal(r.categories['blocked-stage2'].size, 64 * 364)
  assert.equal(r.categories['blocked-stage1'].size, 128 * 364)
  for (const cat of [
    r.categories.pass,
    r.categories['blocked-stage1'],
    r.categories['blocked-stage2'],
  ]) {
    assert.equal(cat.regions.reduce((s, g) => s + g.size, 0), cat.size)
    for (const g of cat.groups) {
      assert.equal(g.regions.reduce((s, x) => s + x.size, 0), g.size)
    }
  }
})

test('轨迹分组按两阶段首命中者聚合：两条一阶段规则产生两个通过分组', () => {
  const stage1 = [
    rule({ id: 'a1', name: 'A1', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'a2', name: 'A2', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'allow' }),
  ]
  const stage2 = [rule({ id: 'b', name: 'B', cidr: '0.0.0.0/0', protocol: 'TCP', action: 'allow' })]
  const target = {
    cidr: '10.0.0.0/24',
    portStart: '0',
    portEnd: '65535',
    protocol: 'TCP' as const,
  }
  const { target: normalized } = validateTandemTarget(target)
  const r = analyzeTandem(stage1, stage2, ['allow'], ['allow'], normalized!)
  const groups = r.categories.pass.groups
  assert.equal(groups.length, 2)
  assert.deepEqual(groups.map((g) => [g.stage1?.name, g.stage2?.name]), [
    ['A1', 'B'],
    ['A2', 'B'],
  ])
  assert.equal(groups[0].size, 128 * 65536)
  assert.equal(groups[1].size, 128 * 65536)
})

test('所有类别与分组的代表报文暴力串联重放，轨迹与分组完全一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/26', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.0/24', portStart: '443', portEnd: '8080', action: 'deny' }),
  ]
  const stage2 = [
    rule({ id: 'b', name: 'B', cidr: '10.0.0.0/27', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const target = {
    cidr: '10.0.0.0/24',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY' as const,
  }
  const { target: normalized } = validateTandemTarget(target)
  const r = analyzeTandem(stage1, stage2, ['allow'], ['allow'], normalized!)

  const replay = (p: { srcIp: string; srcPort: number; protocol: 'TCP' | 'UDP' }) => {
    const ipNum = ipv4ToInt(p.srcIp)
    const h1 = bruteHit(stage1, ipNum, p.srcPort, p.protocol)
    const entered = h1 !== undefined && h1.action === 'allow'
    const h2 = entered ? bruteHit(stage2, ipNum, p.srcPort, p.protocol) : undefined
    return { h1, entered, h2 }
  }

  for (const cat of [
    r.categories.pass,
    r.categories['blocked-stage1'],
    r.categories['blocked-stage2'],
  ]) {
    for (const p of cat.examples) {
      const t = replay(p)
      assert.equal(t.h1?.name ?? null, p.stage1?.name ?? null)
      assert.equal(t.entered, p.enteredStage2)
      if (t.entered) assert.equal(t.h2?.name ?? null, p.stage2?.name ?? null)
    }
    for (const g of cat.groups) {
      const t = replay(g.packet)
      assert.equal(t.h1?.name ?? null, g.stage1?.name ?? null)
      assert.equal(t.h1?.action ?? null, g.stage1?.action ?? null)
      assert.equal(t.entered, g.enteredStage2)
      if (t.entered) {
        assert.equal(t.h2?.name ?? null, g.stage2?.name ?? null)
        assert.equal(t.h2?.action ?? null, g.stage2?.action ?? null)
      }
    }
  }
  // 三类都应非空
  assert.ok(r.categories.pass.cells > 0)
  assert.ok(r.categories['blocked-stage1'].cells > 0)
  assert.ok(r.categories['blocked-stage2'].cells > 0)
})

test('同一输入重复分析结果完全确定（含分组、区域与代表报文）', () => {
  const stage1 = [
    rule({ name: 'A', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ name: 'A2', cidr: '0.0.0.0/0', action: 'deny' }),
  ]
  const stage2 = [rule({ name: 'B', cidr: '10.0.0.0/8', action: 'permit' })]
  const target = { cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' as const }
  const { target: normalized } = validateTandemTarget(target)
  const fixed = new Date('2026-04-01T00:00:00Z')
  const r1 = analyzeTandem(stage1, stage2, ['allow', 'permit'], ['permit'], normalized!, fixed)
  const r2 = analyzeTandem(stage1, stage2, ['allow', 'permit'], ['permit'], normalized!, fixed)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)))
})

console.log(`\n双级串联策略 ${passed} 项测试通过 ✔`)
