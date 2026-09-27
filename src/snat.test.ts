/**
 * 源地址转换路径分析引擎自检：
 * 映射解析（等长 / 重叠 / 格式错误）、目标必须完全落在映射源网段、
 * 输入错误阻止分析、前级按原始地址首命中、仅放行报文按主机位映射后
 * 进入后级、后级 CIDR 边界逆映射切分、三类精确划分、ANY 分协议统计、
 * 非法 / 停用规则两级排除与计数、代表报文（含转换后地址）可暴力复现、
 * 精确区域行合计、确定性。
 */
import assert from 'node:assert'
import {
  analyzeSnat,
  evaluateSnat,
  parseSnatMappings,
  preimageRanges,
  targetCoveredByMappings,
} from './audit/snat'
import type { NormalizedSnatMapping, SnatFormInput } from './audit/snat'
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

const MAPPINGS = '10.0.0.0/24 -> 192.168.0.0/24'
const TARGET = {
  cidr: '10.0.0.0/24',
  portStart: '0',
  portEnd: '65535',
  protocol: 'TCP',
}

function form(partial: Partial<SnatFormInput> = {}): SnatFormInput {
  return {
    stage2Json: partial.stage2Json ?? '[]',
    allow1Text: partial.allow1Text ?? 'allow',
    allow2Text: partial.allow2Text ?? 'allow',
    mappingsText: partial.mappingsText ?? MAPPINGS,
    target: partial.target ?? TARGET,
  }
}

function json(rules: Array<Partial<RuleInput>>): string {
  return JSON.stringify(rules.map((r) => rule(r)))
}

function mappingOf(text: string): NormalizedSnatMapping[] {
  const { mappings, errors } = parseSnatMappings(text)
  assert.deepEqual(errors, [])
  return mappings
}

function targetOf(input: {
  cidr: string
  portStart: string
  portEnd: string
  protocol: string
}) {
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
// 映射解析与校验
// ---------------------------------------------------------------------------

test('映射解析：多行、多种分隔符、忽略空行、规范化输出', () => {
  const { mappings, errors } = parseSnatMappings(
    '10.0.0.0/24 -> 192.168.0.0/24\n' +
      '\n' +
      '10.0.1.0/25→192.168.1.0/25\n' +
      '10.0.1.128/25 => 192.168.1.128/25\n' +
      '10.0.2.0/24, 192.168.2.0/24\n' +
      '10.0.3.0/24 192.168.3.0/24',
  )
  assert.deepEqual(errors, [])
  assert.equal(mappings.length, 5)
  assert.equal(mappings[0].sourceText, '10.0.0.0/24')
  assert.equal(mappings[0].translatedText, '192.168.0.0/24')
  assert.equal(mappings[1].prefix, 25)
  assert.equal(mappings[4].sourceText, '10.0.3.0/24')
})

test('映射格式错误：行内网段数不为 2、CIDR 非法、前缀不等长', () => {
  let out = parseSnatMappings('10.0.0.0/24')
  assert.ok(out.errors.some((e) => e.includes('第 1 行') && e.includes('应形如')))

  out = parseSnatMappings('10.0.0.0/24 -> 192.168.0.0/24 -> 1.2.3.0/24')
  assert.ok(out.errors.some((e) => e.includes('第 1 行')))

  out = parseSnatMappings('10.0.0.5/24 -> 192.168.0.0/24')
  assert.ok(out.errors.some((e) => e.includes('第 1 行源网段') && e.includes('主机位非零')))

  out = parseSnatMappings('10.0.0.0/24 -> 192.168.0.5/24')
  assert.ok(out.errors.some((e) => e.includes('第 1 行转换后网段')))

  out = parseSnatMappings('10.0.0.0/24 -> 192.168.0.0/25')
  assert.ok(out.errors.some((e) => e.includes('前缀长度不一致') && e.includes('等长')))
})

test('映射为空或源网段重叠：拒绝', () => {
  let out = parseSnatMappings('  \n ')
  assert.ok(out.errors.some((e) => e.includes('源地址映射不能为空')))

  out = parseSnatMappings('10.0.0.0/24 -> 192.168.0.0/24\n10.0.0.128/25 -> 192.168.1.0/25')
  assert.ok(out.errors.some((e) => e.includes('重叠') && e.includes('10.0.0.0/24') && e.includes('10.0.0.128/25')))

  // 完全相同的源网段也算重叠
  out = parseSnatMappings('10.0.0.0/24 -> 192.168.0.0/24\n10.0.0.0/24 -> 192.168.9.0/24')
  assert.ok(out.errors.some((e) => e.includes('重叠')))
})

test('目标必须完全落在映射源网段内（跨相邻网段合法，跨空隙非法）', () => {
  const m = mappingOf('10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 192.168.0.128/25')
  assert.equal(targetCoveredByMappings(targetOf({ ...TARGET, cidr: '10.0.0.0/24' }), m), true)
  assert.equal(targetCoveredByMappings(targetOf({ ...TARGET, cidr: '10.0.0.0/25' }), m), true)

  // 目标超出并集右端
  assert.equal(
    targetCoveredByMappings(targetOf({ ...TARGET, cidr: '10.0.0.0/23' }), m),
    false,
  )
  // 目标完全落在映射之外
  assert.equal(
    targetCoveredByMappings(targetOf({ ...TARGET, cidr: '10.0.1.0/24' }), m),
    false,
  )
  // 映射间有空隙，目标跨空隙
  const gapped = mappingOf('10.0.0.0/25 -> 192.168.0.0/25\n10.0.1.0/25 -> 192.168.1.0/25')
  assert.equal(targetCoveredByMappings(targetOf({ ...TARGET, cidr: '10.0.0.0/24' }), gapped), false)

  // evaluate 整体报错并阻止分析
  const out = evaluateSnat(
    [rule({ name: 'A', cidr: '10.0.0.0/24' })],
    form({
      mappingsText: '10.0.0.0/25 -> 192.168.0.0/25',
      stage2Json: json([{ name: 'B', cidr: '192.168.0.0/25' }]),
    }),
  )
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('未完全落在映射源网段内')))
})

test('输入错误阻止分析：目标 / 放行列表 / 后级 JSON（规则级非法不阻止）', () => {
  let out = evaluateSnat([rule({})], form({ target: { ...TARGET, cidr: '10.0.0.5/24' } }))
  assert.equal(out.ok, false)
  assert.ok(!out.ok && out.errors.some((e) => e.includes('主机位非零')))

  out = evaluateSnat([rule({})], form({ allow1Text: ' ' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('前级放行动作列表不能为空')))

  out = evaluateSnat([rule({})], form({ allow2Text: '' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级放行动作列表不能为空')))

  out = evaluateSnat([rule({})], form({ stage2Json: '' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级规则 JSON 不能为空')))

  out = evaluateSnat([rule({})], form({ stage2Json: 'not json' }))
  assert.ok(!out.ok && out.errors.some((e) => e.includes('后级 JSON')))

  out = evaluateSnat([rule({})], form({ stage2Json: '[{"cidr":"10/8"}]' }))
  assert.equal(out.ok, true) // 规则级非法：保留并按既有语义排除，不阻止分析
})

// ---------------------------------------------------------------------------
// 转换路径语义
// ---------------------------------------------------------------------------

test('两级放行：目标全部最终通过，代表报文含按主机位平移的转换后地址', () => {
  const stage1 = [rule({ id: 'a', name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnat(
    stage1,
    form({ stage2Json: json([{ id: 'b', name: 'B', cidr: '192.168.0.0/24', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  const total = 256 * 65536
  assert.equal(r.totalSize, total)
  assert.equal(r.categories.pass.size, total)
  assert.equal(r.categories['blocked-stage1'].size, 0)
  assert.equal(r.categories['blocked-stage2'].size, 0)
  assert.equal(r.categories.pass.groups.length, 1)
  const g = r.categories.pass.groups[0]
  assert.equal(g.stage1?.name, 'A')
  assert.equal(g.stage2?.name, 'B')
  // 代表报文：块内第 2 个地址、段首端口；转换后地址 = 主机位平移
  assert.deepEqual(r.categories.pass.examples, [
    {
      srcIp: '10.0.0.1',
      srcPort: 0,
      protocol: 'TCP',
      translatedSrcIp: '192.168.0.1',
      stage1: g.stage1,
      enteredStage2: true,
      stage2: g.stage2,
    },
  ])
})

test('前级按原始地址首命中：只匹配转换后网段的前级规则不命中', () => {
  const stage1 = [rule({ name: 'A', cidr: '192.168.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnat(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '192.168.0.0/24', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage1'].size, 256 * 65536)
  assert.equal(r.categories.pass.size, 0)
})

test('后级按转换后地址首命中：只匹配原始网段的后级规则不命中', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnat(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '10.0.0.0/24', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage2'].size, 256 * 65536)
  assert.equal(r.categories['blocked-stage2'].groups[0].stage2, null)
})

test('前级阻断：不发生转换（代表报文无转换后地址），不进入后级', () => {
  const stage1 = [rule({ name: 'D', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny' })]
  const out = evaluateSnat(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '192.168.0.0/24', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage1'].size, 256 * 65536)
  const g = r.categories['blocked-stage1'].groups[0]
  assert.equal(g.stage1?.action, 'deny')
  assert.equal(g.enteredStage2, false)
  assert.equal(g.stage2, null)
  assert.equal(g.packet.translatedSrcIp, null)
  assert.equal(r.categories['blocked-stage1'].examples[0].translatedSrcIp, null)
})

test('后级阻断：未命中与动作不放行分别成组，代表报文含转换后地址', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  // 后级只覆盖转换后网段后半且动作 drop：前半未命中、后半动作不放行
  const out = evaluateSnat(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '192.168.0.128/25', protocol: 'TCP', action: 'drop' }]),
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories['blocked-stage2'].size, 256 * 65536)
  assert.equal(r.categories['blocked-stage2'].groups.length, 2)
  const noHit = r.categories['blocked-stage2'].groups.find((g) => g.stage2 === null)!
  const dropped = r.categories['blocked-stage2'].groups.find((g) => g.stage2 !== null)!
  assert.equal(noHit.size, 128 * 65536)
  assert.equal(dropped.size, 128 * 65536)
  assert.equal(dropped.stage2?.action, 'drop')
  // 两组代表报文都进入了后级：含转换后地址
  assert.equal(noHit.packet.translatedSrcIp, '192.168.0.1')
  assert.equal(dropped.packet.translatedSrcIp, '192.168.0.129')
})

test('后级 CIDR 边界逆映射切分：转换后空间的一半精确对应原始空间的一半', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnat(
    stage1,
    form({ stage2Json: json([{ name: 'B', cidr: '192.168.0.0/25', protocol: 'TCP' }]) }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories.pass.size, 128 * 65536)
  assert.equal(r.categories['blocked-stage2'].size, 128 * 65536)
  // 区域以原始地址空间展示
  assert.deepEqual(r.categories.pass.regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.0/25'], size: 128 * 65536 },
  ])
  assert.deepEqual(r.categories['blocked-stage2'].regions[0].rows, [
    { portStart: 0, portEnd: 65535, cidrs: ['10.0.0.128/25'], size: 128 * 65536 },
  ])
})

test('多条映射：目标跨相邻源网段，各自按所在网段的主机位转换', () => {
  const mappingsText = '10.0.0.0/25 -> 192.168.0.0/25\n10.0.0.128/25 -> 10.1.0.0/25'
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  // 后级只放行 10.1.0.0/25：只有原始 10.0.0.128/25（映射到 10.1.0.0/25）通过
  const out = evaluateSnat(
    stage1,
    form({
      mappingsText,
      stage2Json: json([{ name: 'B', cidr: '10.1.0.0/25', protocol: 'TCP' }]),
    }),
  )
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.equal(r.categories.pass.size, 128 * 65536)
  assert.equal(r.categories['blocked-stage2'].size, 128 * 65536)
  assert.deepEqual(r.categories.pass.regions[0].rows[0].cidrs, ['10.0.0.128/25'])
  // 通过类别的代表报文：原始 10.0.0.129 → 转换后 10.1.0.1
  const p = r.categories.pass.examples[0]
  assert.equal(p.srcIp, '10.0.0.129')
  assert.equal(p.translatedSrcIp, '10.1.0.1')
})

test('逆映射区间：与转换后网段求交后按主机位平移回源网段', () => {
  const m = mappingOf('10.0.0.0/24 -> 192.168.0.0/24\n10.0.1.0/24 -> 192.168.1.0/24')
  // 横跨两个转换后网段的规则 → 两段逆映射区间
  assert.deepEqual(preimageRanges({ ipStart: ipv4ToInt('192.168.0.0'), ipEnd: ipv4ToInt('192.168.1.255') }, m), [
    { start: ipv4ToInt('10.0.0.0'), end: ipv4ToInt('10.0.0.255') },
    { start: ipv4ToInt('10.0.1.0'), end: ipv4ToInt('10.0.1.255') },
  ])
  // 部分相交
  assert.deepEqual(
    preimageRanges({ ipStart: ipv4ToInt('192.168.0.128'), ipEnd: ipv4ToInt('192.168.0.191') }, m),
    [{ start: ipv4ToInt('10.0.0.128'), end: ipv4ToInt('10.0.0.191') }],
  )
  // 不相交 → 空
  assert.deepEqual(
    preimageRanges({ ipStart: ipv4ToInt('203.0.113.0'), ipEnd: ipv4ToInt('203.0.113.255') }, m),
    [],
  )
})

test('三分类精确划分：三类与各轨迹分组的区域行合计均与单元级大小一致', () => {
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/25', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.128/25', protocol: 'TCP', action: 'deny' }),
  ]
  const stage2 = [rule({ id: 'b', name: 'B', cidr: '192.168.0.0/26', protocol: 'TCP', action: 'allow' })]
  const target = targetOf({ cidr: '10.0.0.0/24', portStart: '80', portEnd: '443', protocol: 'TCP' })
  const r = analyzeSnat(stage1, stage2, ['allow'], ['allow'], mappingOf(MAPPINGS), target)
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

test('ANY 目标分协议统计：TCP 通过、UDP 前级未命中阻断', () => {
  const stage1 = [rule({ name: 'A', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const out = evaluateSnat(
    stage1,
    form({
      stage2Json: json([{ name: 'B', cidr: '192.168.0.0/24' }]),
      target: { ...TARGET, protocol: 'ANY' },
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
    rule({ id: 'ok', name: 'OK', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }),
    rule({ id: 'off', name: 'OFF', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'deny', enabled: false }),
    rule({ id: 'bad', name: 'BAD', cidr: '10.0.0.5/24', protocol: 'TCP', action: 'deny' }),
  ]
  const stage2 = [
    { id: 'ok2', name: 'OK2', cidr: '192.168.0.0/24', portStart: 0, portEnd: 65535, protocol: 'TCP', action: 'allow' },
    { id: 'off2', name: 'OFF2', cidr: '0.0.0.0/0', portStart: 0, portEnd: 65535, protocol: 'ANY', action: 'deny', enabled: false },
    { id: 'bad2', name: 'BAD2', cidr: '192.168.0.5/24', portStart: 0, portEnd: 65535, protocol: 'TCP', action: 'deny' },
  ]
  const out = evaluateSnat(stage1, form({ stage2Json: JSON.stringify(stage2) }))
  if (!out.ok) throw new Error(JSON.stringify(out.errors))
  const r = out.result
  assert.deepEqual(r.stage1, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.deepEqual(r.stage2, { total: 3, active: 1, invalid: 1, disabled: 1 })
  assert.equal(r.categories.pass.size, 256 * 65536)
})

test('所有类别与分组的代表报文暴力重放：轨迹与转换后地址完全一致', () => {
  const mappingsText = '10.0.0.0/26 -> 192.168.1.0/26\n10.0.0.64/26 -> 192.168.1.64/26'
  const mappings = mappingOf(mappingsText)
  const stage1 = [
    rule({ id: 'a', name: 'A', cidr: '10.0.0.0/26', portStart: '80', portEnd: '443', action: 'allow' }),
    rule({ id: 'd', name: 'D', cidr: '10.0.0.0/25', portStart: '443', portEnd: '8080', action: 'deny' }),
  ]
  const stage2 = [
    rule({ id: 'b', name: 'B', cidr: '192.168.1.0/27', portStart: '80', portEnd: '443', protocol: 'TCP', action: 'allow' }),
  ]
  const target = targetOf({ cidr: '10.0.0.0/25', portStart: '0', portEnd: '65535', protocol: 'ANY' })
  const r = analyzeSnat(stage1, stage2, ['allow'], ['allow'], mappings, target)

  const replay = (p: { srcIp: string; srcPort: number; protocol: 'TCP' | 'UDP' }) => {
    const ipNum = ipv4ToInt(p.srcIp)
    const h1 = bruteHit(stage1, ipNum, p.srcPort, p.protocol)
    const entered = h1 !== undefined && h1.action === 'allow'
    const m = mappings.find((x) => ipNum >= x.srcStart && ipNum <= x.srcEnd)!
    const tip = (m.dstStart + (ipNum - m.srcStart)) >>> 0
    const h2 = entered ? bruteHit(stage2, tip, p.srcPort, p.protocol) : undefined
    return { h1, entered, h2, tip }
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
      if (t.entered) {
        assert.equal(t.h2?.name ?? null, p.stage2?.name ?? null)
        assert.equal(p.translatedSrcIp, intToIpv4(t.tip))
      } else {
        assert.equal(p.translatedSrcIp, null)
      }
    }
    for (const g of cat.groups) {
      const t = replay(g.packet)
      assert.equal(t.h1?.name ?? null, g.stage1?.name ?? null)
      assert.equal(t.h1?.action ?? null, g.stage1?.action ?? null)
      assert.equal(t.entered, g.enteredStage2)
      if (t.entered) {
        assert.equal(t.h2?.name ?? null, g.stage2?.name ?? null)
        assert.equal(t.h2?.action ?? null, g.stage2?.action ?? null)
        assert.equal(g.packet.translatedSrcIp, intToIpv4(t.tip))
      } else {
        assert.equal(g.packet.translatedSrcIp, null)
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
  const stage2 = [rule({ name: 'B', cidr: '192.168.0.0/24', action: 'permit' })]
  const target = targetOf({ cidr: '10.0.0.0/24', portStart: '0', portEnd: '65535', protocol: 'ANY' })
  const mappings = mappingOf(MAPPINGS)
  const fixed = new Date('2026-04-01T00:00:00Z')
  const r1 = analyzeSnat(stage1, stage2, ['allow', 'permit'], ['permit'], mappings, target, fixed)
  const r2 = analyzeSnat(stage1, stage2, ['allow', 'permit'], ['permit'], mappings, target, fixed)
  assert.deepStrictEqual(JSON.parse(JSON.stringify(r1)), JSON.parse(JSON.stringify(r2)))
})

console.log(`\n源地址转换路径分析 ${passed} 项测试通过 ✔`)
