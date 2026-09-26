/**
 * 流量样本归因自检：首命中判定、ANY 样本按同一权重分别判定 TCP/UDP、
 * 权重汇总与占比、分组与明细排序、重复 id / 非法字段逐行报错且不计入统计、
 * 非法 / 停用规则排除、JSON 解析失败与空输入。
 */
import assert from 'node:assert'
import { attributeSamples, parseSamplesJson } from './audit/attribution'
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

/** 构造测试规则集：web-deny(TCP 80) → internal(10/8 ANY allow) → dns-deny(UDP 53) */
function makeRules(): RuleInput[] {
  return [
    rule({ name: 'web-deny', cidr: '10.0.0.0/8', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'internal', cidr: '10.0.0.0/8', protocol: 'ANY', action: 'allow' }),
    rule({ name: 'dns-deny', cidr: '0.0.0.0/0', portStart: '53', portEnd: '53', protocol: 'UDP', action: 'deny' }),
  ]
}

const SAMPLES = `[
  { "id": "s1", "srcIp": "10.0.0.5", "srcPort": 80, "protocol": "TCP", "weight": 2 },
  { "id": "s2", "srcIp": "10.0.0.5", "srcPort": 80, "protocol": "UDP", "weight": 2 },
  { "id": "s3", "srcIp": "10.0.0.5", "srcPort": 1234, "protocol": "ANY", "weight": 3 },
  { "id": "s4", "srcIp": "8.8.8.8", "srcPort": 53, "protocol": "UDP", "weight": 1 },
  { "id": "s5", "srcIp": "8.8.8.8", "srcPort": 53, "protocol": "TCP", "weight": 1 },
  { "id": "s6", "srcIp": "8.8.8.8", "srcPort": 53, "protocol": "ANY", "weight": 1 }
]`

test('首命中归因：命中规则与动作正确，权重汇总与占比精确', () => {
  const result = attributeSamples(makeRules(), SAMPLES)
  assert.equal(result.errors.length, 0)
  assert.equal(result.sampleCount, 6)
  // s3 / s6 为 ANY：各产生 TCP、UDP 两条判定 → 8 条判定
  assert.equal(result.judgementCount, 8)
  // 总权重 = 2+2+3+3+1+1+1+1 = 14（ANY 权重在两个协议各计一次）
  assert.equal(result.totalWeight, 14)

  // 分组：internal 8（s2=2 + s3 TCP/UDP 各 3）、web-deny 2、dns-deny 2（s4 + s6 UDP）
  assert.equal(result.groups.length, 3)
  const [g0, g1, g2] = result.groups
  assert.equal(g0.matchedRuleName, 'internal')
  assert.equal(g0.action, 'allow')
  assert.equal(g0.weight, 8)
  assert.ok(Math.abs(g0.ratio - 8 / 14) < 1e-9)
  // web-deny 与 dns-deny 同权重，按规则序号升序
  assert.equal(g1.matchedRuleName, 'web-deny')
  assert.equal(g1.weight, 2)
  assert.equal(g2.matchedRuleName, 'dns-deny')
  assert.equal(g2.weight, 2)

  // 未命中：s5（TCP 53）+ s6 的 TCP 判定
  assert.ok(result.unmatched)
  assert.equal(result.unmatched!.weight, 2)
  assert.ok(Math.abs(result.unmatched!.ratio - 2 / 14) < 1e-9)
  assert.equal(result.matchedWeight, 12)
  assert.ok(Math.abs(result.matchedRatio - 12 / 14) < 1e-9)
  // 各组占比合计 = 100%
  const sum =
    result.groups.reduce((s, g) => s + g.ratio, 0) + result.unmatched!.ratio
  assert.ok(Math.abs(sum - 1) < 1e-9)
})

test('ANY 样本按同一权重分别判定 TCP 与 UDP，可落入不同分组', () => {
  const result = attributeSamples(makeRules(), SAMPLES)
  // s6（ANY, 8.8.8.8:53）：UDP 命中 dns-deny，TCP 未命中
  const dns = result.groups.find((g) => g.matchedRuleName === 'dns-deny')!
  const s6udp = dns.judgements.find((j) => j.id === 's6')!
  assert.equal(s6udp.protocol, 'UDP')
  assert.equal(s6udp.weight, 1)
  const s6tcp = result.unmatched!.judgements.find((j) => j.id === 's6')!
  assert.equal(s6tcp.protocol, 'TCP')
  assert.equal(s6tcp.weight, 1)
  assert.equal(s6tcp.matchedRuleIndex, null)
  // s3（ANY, 10.0.0.5:1234）：两个协议都命中 internal，各带权重 3
  const internal = result.groups.find((g) => g.matchedRuleName === 'internal')!
  const s3 = internal.judgements.filter((j) => j.id === 's3')
  assert.equal(s3.length, 2)
  assert.deepEqual(s3.map((j) => j.protocol).sort(), ['TCP', 'UDP'])
  assert.ok(s3.every((j) => j.weight === 3))
})

test('明细按权重降序（同权重按行号升序），行号指向原始数组位置', () => {
  const result = attributeSamples(makeRules(), SAMPLES)
  const internal = result.groups.find((g) => g.matchedRuleName === 'internal')!
  // internal 组：s3 两条（w=3，第 3 条）在前，s2（w=2，第 2 条）在后
  assert.deepEqual(
    internal.judgements.map((j) => [j.id, j.weight]),
    [
      ['s3', 3],
      ['s3', 3],
      ['s2', 2],
    ],
  )
  assert.equal(internal.judgements[0].line, 3)
  // 未命中组：s5（第 5 条）与 s6 的 TCP（第 6 条）同权重，按行号升序
  assert.deepEqual(
    result.unmatched!.judgements.map((j) => j.id),
    ['s5', 's6'],
  )
})

test('重复 id 逐行报错且不计入统计；错误行 id 仍参与查重', () => {
  const text = `[
    { "id": "a", "srcIp": "10.0.0.1", "srcPort": 1, "protocol": "TCP", "weight": 1 },
    { "id": "a", "srcIp": "10.0.0.2", "srcPort": 2, "protocol": "TCP", "weight": 1 },
    { "id": "b", "srcIp": "10.0.0.3", "srcPort": 3, "protocol": "TCP", "weight": 4 },
    { "id": "c", "srcIp": "10.0.0.4", "srcPort": 99999, "protocol": "TCP", "weight": 1 },
    { "id": "c", "srcIp": "10.0.0.5", "srcPort": 5, "protocol": "TCP", "weight": 1 }
  ]`
  const result = attributeSamples(makeRules(), text)
  // 第 2 条重复 a；第 4 条端口越界；第 5 条重复 c（c 首次出现于错误行，仍登记）
  assert.equal(result.errors.length, 3)
  assert.equal(result.errors[0].line, 2)
  assert.match(result.errors[0].errors[0], /重复/)
  assert.equal(result.errors[1].line, 4)
  assert.match(result.errors[1].errors[0], /srcPort/)
  assert.equal(result.errors[2].line, 5)
  assert.match(result.errors[2].errors[0], /重复/)
  // 仅 a、b 两条合法样本计入
  assert.equal(result.sampleCount, 2)
  assert.equal(result.totalWeight, 5)
  assert.equal(result.groups.length, 1)
  assert.equal(result.groups[0].weight, 5)
})

test('非法字段逐行报错：一行可多个错误，合法行不受影响', () => {
  const text = `[
    { "id": "ok", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP", "weight": 2 },
    "not-an-object",
    { "id": "", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP", "weight": 1 },
    { "id": "bad-ip", "srcIp": "10.0.0", "srcPort": 80, "protocol": "TCP", "weight": 1 },
    { "id": "bad-ip2", "srcIp": "999.1.1.1", "srcPort": 80, "protocol": "TCP", "weight": 1 },
    { "id": "bad-port", "srcIp": "10.0.0.1", "srcPort": 1.5, "protocol": "TCP", "weight": 1 },
    { "id": "bad-port2", "srcIp": "10.0.0.1", "srcPort": -1, "protocol": "TCP", "weight": 1 },
    { "id": "bad-proto", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "ICMP", "weight": 1 },
    { "id": "w-zero", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP", "weight": 0 },
    { "id": "w-neg", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP", "weight": -3 },
    { "id": "w-text", "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP", "weight": "abc" },
    { "id": "multi", "srcIp": "nope", "srcPort": "x", "protocol": "?", "weight": -1 },
    { "srcIp": "10.0.0.1", "srcPort": 80, "protocol": "TCP" }
  ]`
  const result = attributeSamples(makeRules(), text)
  // 除第 1 条外全部报错（12 行错误）
  assert.equal(result.errors.length, 12)
  assert.equal(result.sampleCount, 1)
  assert.equal(result.totalWeight, 2)
  // 非对象行
  assert.equal(result.errors[0].line, 2)
  assert.match(result.errors[0].errors[0], /不是对象/)
  // 一行多错：multi 行同时报 srcIp / srcPort / protocol / weight 四类错误
  const multi = result.errors.find((e) => e.id === 'multi')!
  assert.equal(multi.line, 12)
  assert.equal(multi.errors.length, 4)
  // 缺字段行：id 与 weight 均缺失
  const last = result.errors[result.errors.length - 1]
  assert.equal(last.line, 13)
  assert.equal(last.id, null)
  assert.ok(last.errors.some((e) => e.includes('id')))
  assert.ok(last.errors.some((e) => e.includes('weight')))
})

test('id 接受数字并转为字符串查重；协议大小写不敏感；权重接受数字字符串', () => {
  const text = `[
    { "id": 7, "srcIp": "10.0.0.1", "srcPort": "80", "protocol": "tcp", "weight": "2.5" },
    { "id": "7", "srcIp": "10.0.0.2", "srcPort": 80, "protocol": "TCP", "weight": 1 }
  ]`
  const result = attributeSamples(makeRules(), text)
  assert.equal(result.errors.length, 1)
  assert.equal(result.errors[0].line, 2)
  assert.match(result.errors[0].errors[0], /重复/)
  assert.equal(result.sampleCount, 1)
  assert.equal(result.totalWeight, 2.5)
  assert.equal(result.groups[0].matchedRuleName, 'web-deny')
})

test('非法与停用规则不参与判定', () => {
  const rules = [
    rule({ name: 'off', cidr: '10.0.0.0/8', protocol: 'ANY', action: 'deny', enabled: false }),
    rule({ name: 'bad', cidr: '10.0.0.5/24', protocol: 'ANY', action: 'deny' }),
    rule({ name: 'tcp-only', cidr: '0.0.0.0/0', protocol: 'TCP', action: 'allow' }),
  ]
  const text = `[
    { "id": "a", "srcIp": "10.0.0.5", "srcPort": 80, "protocol": "TCP", "weight": 1 },
    { "id": "b", "srcIp": "10.0.0.5", "srcPort": 80, "protocol": "UDP", "weight": 1 }
  ]`
  const result = attributeSamples(rules, text)
  assert.equal(result.activeRuleCount, 1)
  assert.equal(result.invalidExcluded, 1)
  assert.equal(result.disabledExcluded, 1)
  // TCP 样本越过停用 / 非法规则命中 tcp-only；UDP 样本未命中
  assert.equal(result.groups.length, 1)
  assert.equal(result.groups[0].matchedRuleName, 'tcp-only')
  assert.equal(result.unmatched!.weight, 1)
})

test('JSON 解析失败、非数组根节点与空输入均整体报错', () => {
  for (const text of ['{not json', '{"samples":[]}', '42', '  ']) {
    const result = attributeSamples(makeRules(), text)
    assert.equal(result.sampleCount, 0)
    assert.equal(result.totalWeight, 0)
    assert.equal(result.errors.length, 1)
    assert.equal(result.errors[0].line, 0)
  }
  assert.match(attributeSamples(makeRules(), '{not json').errors[0].errors[0], /JSON 解析失败/)
  assert.match(attributeSamples(makeRules(), '{"samples":[]}').errors[0].errors[0], /数组/)
})

test('空数组与无合法启用规则：结果为空但不报错', () => {
  const empty = attributeSamples(makeRules(), '[]')
  assert.equal(empty.errors.length, 0)
  assert.equal(empty.sampleCount, 0)
  assert.equal(empty.judgementCount, 0)
  assert.equal(empty.totalWeight, 0)
  assert.equal(empty.groups.length, 0)
  assert.equal(empty.unmatched, null)

  const noRules = attributeSamples(
    [],
    `[{ "id": "a", "srcIp": "1.2.3.4", "srcPort": 1, "protocol": "ANY", "weight": 2 }]`,
  )
  assert.equal(noRules.activeRuleCount, 0)
  assert.equal(noRules.judgementCount, 2)
  assert.equal(noRules.groups.length, 0)
  assert.equal(noRules.unmatched!.weight, 4)
  assert.equal(noRules.unmatchedRatio, 1)
})

test('结果确定可复现：同一输入两次执行完全一致', () => {
  const now = new Date('2026-09-18T00:00:00Z')
  const r1 = attributeSamples(makeRules(), SAMPLES, now)
  const r2 = attributeSamples(makeRules(), SAMPLES, now)
  assert.deepEqual(r1, r2)
})

test('parseSamplesJson 单独可用：合法样本携带规范化字段', () => {
  const { samples, errors } = parseSamplesJson(
    `[{ "id": " x ", "srcIp": "010.0.0.1", "srcPort": "443", "protocol": "any", "weight": "1e1" }]`,
  )
  assert.equal(errors.length, 0)
  assert.equal(samples.length, 1)
  const s = samples[0]
  assert.equal(s.id, 'x')
  assert.equal(s.ipText, '10.0.0.1')
  assert.equal(s.port, 443)
  assert.equal(s.protocol, 'ANY')
  assert.equal(s.weight, 10)
  assert.equal(s.line, 1)
})

console.log(`\n流量样本归因 ${passed} 项测试通过 ✔`)
