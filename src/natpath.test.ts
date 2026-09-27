/**
 * 源地址转换路径分析引擎自检：
 * 映射解析（等长 / 重叠 / 空）、目标必须完全落在映射源网段、输入错误阻止分析、
 * 前级按原地址首命中（未命中 / 动作不放行即阻断且不转换）、仅放行报文按主机位
 * 一一转换后进入后级、后级 CIDR 边界逆映射回原空间精确切分、三类精确划分、
 * ANY 分协议统计、非法 / 停用规则两级排除与计数、多映射、轨迹分组与
 * 代表报文（含转换后地址）可暴力复现、精确区域行合计、确定性。
 */
import assert from 'node:assert'
import {
  analyzeNatPath,
  evaluateNatPath,
  firstUncoveredIp,
  parseNatMappings,
} from './audit/natpath'
import type { NatPathFormInput } from './audit/natpath'
import { validateTandemTarget } from './audit/tandem'
import { validateRules } from './audit/engine'
import { intToIpv4, ipv4ToInt } from './audit/iputil'
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

const TARGET_24 = {
  cidr: '10.0.0.0/24',
  portStart: '0',
  portEnd: '65535',
  protocol: 'TCP',
}

const MAPPING_24 = '10.0.0.0/24 -> 172.16.0.0/24'

function form(partial: Partial<NatPathFormInput> = {}): NatPathFormInput {
  return {
    stage2Json: partial.stage2Json ?? '[]',
    allow1Text: partial.allow1Text ?? 'allow',
    allow2Text: partial.allow2Text ?? 'allow',
    mappingText: partial.mappingText ?? MAPPING_24,
    target: partial.target ?? TARGET_24,
  }
}

function json(rules: Array<Partial<RuleInput>>): string {
  return JSON.stringify(rules.map((r) => rule(r)))
}

function mappingsOf(text: string) {
  const { mappings, errors } = parseNatMappings(text)
  assert.deepEqual(errors, [])
  return mappings
}

function targetOf(input: { cidr: string; portStart: string; portEnd: string; protocol: string }) {
  const { target, errors } = validateTandemTarget(input)
  assert.deepEqual(errors, [])
  return target!
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
// 映射解析与目标覆盖校验
// ---------------------------------------------------------------------------

test('映射解析：-> 与 → 分隔符、空行跳过、delta 与规范文本', () => {
  const { mappings, errors } = parseNatMappings(
    '10.0.0.0/24 -> 172.16.0.0/24\n\n  \n10.0.1.0/24 → 172.16.1.0/24',
  )
  assert.deepEqual(errors, [])
  assert.equal(mappings.length, 2)
  assert.equal(mappings[0].fromText, '10.0.0.0/24')
  assert.equal(mappings[0].toText, '172.16.0.0/24')
  assert.equal(mappings[0].delta, ipv4ToInt('172.16.0.0') - ipv4ToInt('10.0.0.0'))
  assert.equal(mappings[1].fromText, '10.0.1.0/24')
})

test('映射解析错误：行格式 / CIDR 非法 / 前缀不等长 / 空文本', () => {
  let out = parseNatMappings('10.0.0.0/24')
  assert.ok(out.errors.some((e) => e.includes('映射须形如')))

  out = parseNatMappings('10.0.0.5/24 -> 172.16.0.0/24')
  assert.ok(out.errors.some((e) => e.includes('源网段') && e.includes('主机位非零')))

  out = parseNatMappings('10.0.0.0/24 -> 172.16.0.0/25')
  assert.ok(out.errors.some((e) => e.includes('前缀长度必须相等')))

  out = parseNatMappings('   \n ')
  assert.ok(out.errors.some((e) => e.includes('源地址映射不能为空')))
})

test('映射重叠：源网段重叠与转换后网段重叠分别报错', () => {
  let out = parseNatMappings('10.0.0.0/24 -> 172.16.0.0/24\n10.0.0.128/25 -> 172.16.1.0/25')
  assert.ok(out.errors.some((e) => e.includes('映射源网段重叠')))

  out = parseNatMappings('10.0.0.0/24 -> 172.16.0.0/24\n10.0.1.0/25 -> 172.16.0.128/25')
  assert.ok(out.errors.some((e) => e.includes('转换后网段重叠') && e.includes('逆映射不唯一')))

  // 完全相同的映射重复出现：两侧都重叠
  out = parseNatMappings(`${MAPPING_24}\n${MAPPING_24}`)
  assert.ok(out.errors.some((e) => e.includes('映射源网段重叠')))
})

test('firstUncoveredIp：完全覆盖返回 null，缺口返回首个未覆盖地址', () => {
  const m = mappingsOf('10.0.0.0/25 -> 172.16.0.0/25\n10.0.0.128/25 -> 172.16.1.0/25')
  assert.equal(firstUncoveredIp(m, ipv4ToInt('10.0.0.0'), ipv4ToInt('10.0.0.255')), null)
  assert.equal(
    firstUncoveredIp(m, ipv4ToInt('10.0.0.0'), ipv4ToInt('10.0.1.255')),
    ipv4ToInt('10.0.1.0'),
  )
  // 中间缺口：/26 + /26 之间空出 10.0.0.64/26
  const gapped = mappingsOf('10.0.0.0/26 -> 172.16.0.0/26\n10.0.0.128/26 -> 172.16.1.0/26')
  assert.equal(
    firstUncoveredIp(gapped, ipv4ToInt('10.0.0.0'), ipv4ToInt('10.0.0.255')),
    ipv4ToInt('10.0.0.64'),
  )
})

test('目标未完全落在映射源网段：阻止分析并指出未覆盖地址', () => {
  const out = evaluateNatPath(
    [rule({ name: 'A', cidr: '10.0.0.0/24' })],
    form({ mappingText: '10.0.0.0/25 -> 172.16.0.0/25' }),
  )
  assert.equal(out.ok, false)
  assert.ok(
    !out.ok &&
      out.errors.some((e) => e.includes('未完全落在映射源网段内') && e.includes('10.0.0.128')),
  )
})

test('输入错误阻止分析：空放行列表 / 空或坏 JSON / 目标非法（后级非法规则不阻止）', () => {
  let out = evaluateNatPath([rule({})], form({ allow1Text: '  ' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('前级放行动作列表')))

  out = evaluateNatPath([rule({})], form({ allow2Text: '' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级放行动作列表')))

  out = evaluateNatPath([rule({})], form({ stage2Json: '' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级规则 JSON 不能为空')))

  out = evaluateNatPath([rule({})], form({ stage2Json: 'not json' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级 JSON')))

  out = evaluateNatPath([rule({})], form({ mappingText: '' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('源地址映射不能为空')))

  out = evaluateNatPath([rule({})], form({ target: { ...TARGET_24, cidr: '10.0.0.5/24' } }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('主机位非零')))

  // 后级 JSON 中的规则级非法：保留并按既有语义排除，不阻止分析
  out = evaluateNatPath(
    [rule({ name: 'A', cidr: '10.0.0.0/24' })],
    form({ stage2Json: '[{"cidr":"10/8"}]' }),
  )
  assert.equal(out.ok, true)
})

// ---------------------------------------------------------------------------
// 转换路径语义
// ---------------------------------------------------------------------------

test('前级未命中：前级阻断、不转换（无转换后地址）、不进入后级', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' })]
  const out = evaluateNatPath(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const half = 128 * 65536
  assert.equal(r.categories.pass.size, half)
  assert.equal(r.categories['blocked-stage1'].size, half)
  assert.equal(r.categories['blocked-stage2'].size, 0)
  const g = r.categories['blocked-stage1'].groups[0]
  assert.equal(g.stage1, null)
  assert.equal(g.enteredStage2, false)
  assert.equal(g.stage2, null)
  assert.equal(g.packet.translatedIp, null)
  const ex = r.categories['blocked-stage1'].examples[0]
  assert.equal(ex.translatedIp, null)
  assert.equal(ex.enteredStage2, false)
})

test('前级首命中动作不在放行列表：前级阻断，不转换、不进入后级', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' })]
  const out = evaluateNatPath(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage1'].size, 256 * 65536)
  assert.equal(r.categories.pass.size, 0)
  const g = r.categories['blocked-stage1'].groups[0]
  assert.equal(g.stage1?.action, 'deny')
  assert.equal(g.enteredStage2, false)
  assert.equal(g.packet.translatedIp, null)
})

test('后级边界逆映射：后级只放行转换后 /25，通过区域精确为原空间对应 /25', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateNatPath(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '172.16.0.128/25', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const half = 128 * 65536
  assert.equal(r.totalSize, 256 * 65536)
  assert.equal(r.categories.pass.size, half)
  assert.equal(r.categories['blocked-stage2'].size, half)
  assert.equal(r.categories['blocked-stage1'].size, 0)
  // 通过区域 = 原空间 10.0.0.128/25（后级 172.16.0.128/25 逆映射回原空间）
  assert.deepEqual(r.categories.pass.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.128/25'], size: half },
  ])
  assert.deepEqual(r.categories['blocked-stage2'].regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.0/25'], size: half },
  ])
  // 代表报文含转换后地址与两级命中轨迹
  const p = r.categories.pass.examples[0]
  assert.deepEqual(
    { srcIp: p.srcIp, srcPort: p.srcPort, protocol: p.protocol, translatedIp: p.translatedIp },
    { srcIp: '10.0.0.129', srcPort: 0, protocol: 'TCP', translatedIp: '172.16.0.129' },
  )
  assert.equal(p.stage1?.name, 'A')
  assert.equal(p.enteredStage2, true)
  assert.equal(p.stage2?.name, 'B')
  const b = r.categories['blocked-stage2'].examples[0]
  assert.equal(b.srcIp, '10.0.0.1')
  assert.equal(b.translatedIp, '172.16.0.1')
  assert.equal(b.stage1?.name, 'A')
  assert.equal(b.enteredStage2, true)
  assert.equal(b.stage2, null)
})

test('主机位一一映射（带偏移对齐）：转换后地址 = 原地址 + 偏移量', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/26', protocol: 'TCP', action: 'allow' })]
  const out = evaluateNatPath(
    stage1,
    form({
      mappingText: '10.0.0.0/26 -> 172.16.0.64/26',
      stage2Json: json([{ name: 'B', cidr: '172.16.0.64/26', protocol: 'TCP' }]),
      target: { cidr: '10.0.0.0/26', portStart: '0', portEnd: '65535', protocol: 'TCP' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories.pass.size, 64 * 65536)
  assert.equal(r.categories.pass.size, r.totalSize)
  const p = r.categories.pass.examples[0]
  assert.equal(p.srcIp, '10.0.0.1')
  assert.equal(p.translatedIp, '172.16.0.65')
})

test('多条映射：目标跨两个源网段，各自按所属映射转换', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateNatPath(
    stage1,
    form({
      mappingText: '10.0.0.0/25 -> 172.16.0.0/25\n10.0.0.128/25 -> 172.16.1.0/25',
      stage2Json: json([{ name: 'B', cidr: '172.16.0.0/25', protocol: 'TCP' }]),
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const half = 128 * 65536
  assert.equal(r.categories.pass.size, half)
  assert.equal(r.categories['blocked-stage2'].size, half)
  assert.equal(r.categories.pass.examples[0].translatedIp, '172.16.0.1')
  const b = r.categories['blocked-stage2'].examples[0]
  assert.equal(b.srcIp, '10.0.0.129')
  assert.equal(b.translatedIp, '172.16.1.1')
  assert.equal(b.stage2, null)
})

test('后级未命中与后级动作不放行：均为后级阻断（转换后地址仍标注）', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  // 后级未命中：后级只覆盖转换后空间的另一半
  let out = evaluateNatPath(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '172.16.1.0/24', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  assert.equal(out.result.categories['blocked-stage2'].size, 256 * 65536)
  assert.equal(out.result.categories['blocked-stage2'].groups[0].stage2, null)
  assert.equal(out.result.categories['blocked-stage2'].examples[0].translatedIp, '172.16.0.1')

  // 后级动作不放行
  out = evaluateNatPath(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0', action: 'drop' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  assert.equal(out.result.categories['blocked-stage2'].size, 256 * 65536)
  assert.equal(out.result.categories['blocked-stage2'].groups[0].stage2?.action, 'drop')
})

test('ANY 目标分协议统计：TCP 通过、UDP 前级未命中阻断', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateNatPath(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '0.0.0.0/0' }]),
      target: { ...TARGET_24, protocol: 'ANY' },
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const tcp = out.result.perProtocol.find((p) => p.protocol === 'TCP')!
  const udp = out.result.perProtocol.find((p) => p.protocol === 'UDP')!
  assert.equal(tcp.passSize, 256 * 65536)
  assert.equal(udp.blockedStage1Size, 256 * 65536)
  assert.equal(udp.passSize, 0)
})

test('非法与停用规则在两级均排除并计数', () => {
  const stage1 = [
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/24', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.0/24', action: 'deny', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', action: 'allow' }),
  ]
  const stage2 = [
    { id: 'ok2', name: 'OK2', cidr: '172.16.0.0/24', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'allow' },
    { id: 'off2', name: 'OFF2', cidr: '0.0.0.0/0', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'deny', enabled: false },
    { id: 'bad2', name: 'BAD2', cidr: '172.16.0.5/24', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'allow' },
  ]
  const out = evaluateNatPath(
    stage1,
    form({ stage2Json: JSON.stringify(stage2), target: { ...TARGET_24, protocol: 'ANY' } }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.deepEqual(r.stage1, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.deepEqual(r.stage2, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.equal(r.categories.pass.size, 256 * 65536 * 2)
})

test('三分类精确划分：三类与各轨迹分组的区域行合计均与单元级大小一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ]
  const stage2 = [rule({ id: 'b', name: 'B', cidr: '172.16.0.0/26', protocol: 'TCP', action: 'allow' })]
  const target = targetOf({
    cidr: '10.0.0.0/24',
    portStart: '80',
    portEnd: '443',
    protocol: 'TCP',
  })
  const r = analyzeNatPath(
    stage1,
    stage2,
    ['allow'],
    ['allow'],
    mappingsOf(MAPPING_24),
    target,
  )
  const sum =
    r.categories.pass.size +
    r.categories['blocked-stage1'].size +
    r.categories['blocked-stage2'].size
  assert.equal(sum, r.totalSize)
  // 10.0.0.0/26 通过；10.0.0.64/26 前级放行但转换后未命中；10.0.0.128/25 前级 deny
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

test('轨迹分组按两级首命中者聚合：两条前级规则产生两个通过分组', () => {
  const stage1 = [
    rule({ id: 'a1', name: 'A1', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'a2', name: 'A2', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'allow' }),
  ]
  const stage2 = [rule({ id: 'b', name: 'B', cidr: '0.0.0.0/0', protocol: 'TCP', action: 'allow' })]
  const r = analyzeNatPath(
    stage1,
    stage2,
    ['allow'],
    ['allow'],
    mappingsOf(MAPPING_24),
    targetOf(TARGET_24),
  )
  const groups = r.categories.pass.groups
  assert.equal(groups.length, 2)
  assert.deepEqual(groups.map((g) => [g.stage1?.name, g.stage2?.name]), [
    ['A1', 'B'],
    ['A2', 'B'],
  ])
  assert.equal(groups[0].size, 128 * 65536)
  assert.equal(groups[1].size, 128 * 65536)
  assert.equal(groups[0].packet.translatedIp, '172.16.0.1')
  assert.equal(groups[1].packet.translatedIp, '172.16.0.129')
})

test('所有类别与分组的代表报文暴力转换重放，轨迹与转换后地址完全一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/26', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.0/24', portStart: '443', portEnd: '8080', action: 'deny' }),
  ]
  const stage2 = [
    rule({ id: 'b', name: 'B', cidr: '172.16.0.0/27', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const mappings = mappingsOf(MAPPING_24)
  const target = targetOf({ cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' })
  const r = analyzeNatPath(stage1, stage2, ['allow'], ['allow'], mappings, target)

  const replay = (p: { srcIp: string; srcPort: number; protocol: 'TCP' | 'UDP' }) => {
    const ipNum = ipv4ToInt(p.srcIp)
    const h1 = bruteHit(stage1, ipNum, p.srcPort, p.protocol)
    const entered = h1 !== undefined && h1.action === 'allow'
    let h2: ReturnType<typeof bruteHit>
    let translated: number | null = null
    if (entered) {
      translated = (ipNum + mappings[0].delta) >>> 0
      h2 = bruteHit(stage2, translated, p.srcPort, p.protocol)
    }
    return { h1, entered, h2, translated }
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
      assert.equal(p.translatedIp, t.translated === null ? null : intToIpv4(t.translated))
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
      assert.equal(g.packet.translatedIp, t.translated === null ? null : intToIpv4(t.translated))
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
  const stage2 = [rule({ name: 'B', cidr: '172.16.0.0/16', action: 'permit' })]
  const mappings = mappingsOf(MAPPING_24)
  const target = targetOf({ ...TARGET_24, protocol: 'ANY' })
  const fixed = new Date('2026-04-01T00:00:00Z')
  const r1 = analyzeNatPath(stage1, stage2, ['allow', 'permit'], ['permit'], mappings, target, fixed)
  const r2 = analyzeNatPath(stage1, stage2, ['allow', 'permit'], ['permit'], mappings, target, fixed)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)))
})

console.log(`\n源地址转换路径分析 ${passed} 项测试通过 ✔`)
