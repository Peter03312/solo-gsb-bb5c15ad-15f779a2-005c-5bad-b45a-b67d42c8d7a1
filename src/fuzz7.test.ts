/**
 * 快照对比模糊对照：在缩小且完全可枚举的报文空间（10.1.2.0/24 × 端口 0..31 ×
 * {TCP, UDP}，共 256×32×2 个报文）上随机生成两个规则集，逐报文暴力首命中
 * 两侧规则并分类（动作未变 / 动作改变 / 命中↔未命中），与 compareSnapshots
 * 的类别大小、下钻分组大小逐一对账；并校验：
 *   - 每个分组代表报文暴力重放的前后命中规则 / 动作与分组引用一致；
 *   - 类别精确区域（CIDR × 端口行）恰好覆盖暴力分类到的全部报文、不多不少；
 *   - 区域行合计 == 类别大小；hasActionDifference / hasReassignment 标志正确。
 * 规则 CIDR 全部在 /24 内对齐、端口均在 0..31 内，因此每个枚举报文代表
 * 1 条真实报文空间，引擎大小与枚举计数精确相等。
 */
import assert from 'node:assert'
import { compareSnapshots, createSnapshot } from './audit/snapshot'
import { validateRules } from './audit/engine'
import { intToIpv4, parseCidrStrict } from './audit/iputil'
import type { RuleInput } from './audit/types'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

const BASE = parseCidrStrict('10.1.2.0/24').start
const MAX_PORT = 31
const PROTOS = ['TCP', 'UDP', 'ANY'] as const
const ACTIONS = ['allow', 'deny'] as const

/** /24 内对齐的随机 CIDR，前缀 24..28 */
function randomCidr() {
  const prefix = 24 + rand(5)
  const size = 2 ** (32 - prefix)
  const count = 256 / size
  const start = (BASE + rand(count) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}

function makeRules(): RuleInput[] {
  const n = rand(7)
  return Array.from({ length: n }, (_, i) => {
    const a = rand(MAX_PORT + 1)
    const b = a + rand(MAX_PORT + 1 - a)
    return {
      id: `r${i}`,
      name: `R${i}`,
      cidr: randomCidr(),
      portStart: String(a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(2)],
      enabled: rand(8) !== 0, // 偶发停用
    }
  })
}

interface Hit {
  name: string
  action: string
  index: number
}

function firstHit(valid: ReturnType<typeof validateRules>['valid'], ip: number, port: number, proto: 'TCP' | 'UDP'): Hit | null {
  const active = valid.filter((r) => r.enabled)
  const r = active.find(
    (rule) =>
      ip >= rule.ipStart &&
      ip <= rule.ipEnd &&
      port >= rule.portStart &&
      port <= rule.portEnd &&
      (rule.protocol === 'ANY' || rule.protocol === proto),
  )
  return r ? { name: r.name, action: r.action, index: r.index } : null
}

type Cat = 'unchanged' | 'action-changed' | 'became-unmatched' | 'became-matched'

function classify(before: Hit | null, after: Hit | null): Cat {
  if (!before && after) return 'became-matched'
  if (before && !after) return 'became-unmatched'
  if (before && after && before.action !== after.action) return 'action-changed'
  return 'unchanged'
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const rulesA = makeRules()
  const rulesB = makeRules()
  const { valid: validA } = validateRules(rulesA)
  const { valid: validB } = validateRules(rulesB)
  const diff = compareSnapshots(createSnapshot('a', rulesA), createSnapshot('b', rulesB))

  // 暴力分类累计
  const catCount: Record<Cat, number> = {
    unchanged: 0,
    'action-changed': 0,
    'became-unmatched': 0,
    'became-matched': 0,
  }
  // 暴力分组：类别 × 前名 × 后名 → 计数（undefined = 该侧未命中）
  const groupCount = new Map<string, number>()
  // 类别 → 落在其中的全部暴力报文（供区域覆盖校验）
  const catPackets = new Map<Cat, Array<{ ip: number; port: number; proto: 'TCP' | 'UDP' }>>()
  for (const c of Object.keys(catCount) as Cat[]) catPackets.set(c, [])

  for (let off = 0; off < 256; off++) {
    const ip = (BASE + off) >>> 0
    for (let port = 0; port <= MAX_PORT; port++) {
      for (const proto of ['TCP', 'UDP'] as const) {
        const before = firstHit(validA, ip, port, proto)
        const after = firstHit(validB, ip, port, proto)
        const cat = classify(before, after)
        // 两侧都未命中的报文不参与对比
        if (!before && !after) continue
        catCount[cat]++
        catPackets.get(cat)!.push({ ip, port, proto })
        const key = `${cat}|${before?.name ?? '∅'}|${after?.name ?? '∅'}`
        groupCount.set(key, (groupCount.get(key) ?? 0) + 1)
      }
    }
  }

  // 类别大小对账（每个枚举报文恰为 1 条报文空间）
  for (const cat of Object.keys(catCount) as Cat[]) {
    assert.equal(
      diff.categories[cat].size,
      catCount[cat],
      `round ${round} ${cat}: engine ${diff.categories[cat].size} vs brute ${catCount[cat]}; A=${JSON.stringify(rulesA)} B=${JSON.stringify(rulesB)}`,
    )
    // 区域行合计 == 类别大小
    assert.equal(
      diff.categories[cat].regions.reduce((s, r) => s + r.size, 0),
      catCount[cat],
    )
  }

  // 下钻分组对账：动作未变类别只含同动作易主组（before/after id 不同）
  for (const [key, count] of groupCount) {
    const [catRaw, beforeName, afterName] = key.split('|')
    const cat = catRaw as Cat
    if (cat === 'unchanged' && beforeName === afterName) continue // 命中者未变 → 不建组
    const groups = diff.categories[cat].groups
    const g = groups.find(
      (x) =>
        (x.before?.name ?? null) === (beforeName === '∅' ? null : beforeName) &&
        (x.after?.name ?? null) === (afterName === '∅' ? null : afterName),
    )
    assert.ok(g, `round ${round}: 缺少分组 ${key}; A=${JSON.stringify(rulesA)} B=${JSON.stringify(rulesB)}`)
    assert.equal(g!.size, count, `round ${round}: 分组 ${key} 大小不符`)
  }
  // 反向：引擎分组数 == 暴力期望分组数
  for (const cat of Object.keys(catCount) as Cat[]) {
    const expectedGroups =
      cat === 'unchanged'
        ? [...groupCount.keys()].filter(
            (k) => k.startsWith('unchanged|') && k.split('|')[1] !== k.split('|')[2],
          ).length
        : [...groupCount.keys()].filter((k) => k.startsWith(`${cat}|`)).length
    assert.equal(diff.categories[cat].groups.length, expectedGroups)
  }

  // 精确区域恰好覆盖暴力分类到的报文：逐报文成员判定，要求双向一一对应
  for (const cat of Object.keys(catCount) as Cat[]) {
    const packets = catPackets.get(cat)!
    let inRegion = 0
    for (const pkt of packets) {
      const reg = diff.categories[cat].regions.find((r) => r.protocol === pkt.proto)
      const hitRow = reg?.rows.some(
        (row) =>
          pkt.port >= row.portStart &&
          pkt.port <= row.portEnd &&
          row.cidrs.some((c) => {
            const b = parseCidrStrict(c)
            return pkt.ip >= b.start && pkt.ip <= b.end
          }),
      )
      if (hitRow) inRegion++
    }
    assert.equal(
      inRegion,
      packets.length,
      `round ${round} ${cat}: 区域覆盖 ${inRegion}/${packets.length}`,
    )
  }

  // 每个分组代表报文暴力重放对账
  for (const cat of Object.keys(catCount) as Cat[]) {
    for (const g of diff.categories[cat].groups) {
      const p = g.packet
      const ip = parseCidrStrict(`${p.srcIp}/32`).start
      const before = firstHit(validA, ip, p.srcPort, p.protocol)
      const after = firstHit(validB, ip, p.srcPort, p.protocol)
      assert.equal(before?.name ?? null, g.before?.name ?? null)
      assert.equal(after?.name ?? null, g.after?.name ?? null)
      assert.equal(before?.action ?? null, g.before?.action ?? null)
      assert.equal(after?.action ?? null, g.after?.action ?? null)
    }
  }

  // 标志位
  const expectedActionDiff =
    catCount['action-changed'] + catCount['became-unmatched'] + catCount['became-matched'] > 0
  assert.equal(diff.hasActionDifference, expectedActionDiff)
  const expectedReassign = diff.categories.unchanged.groups.length > 0
  assert.equal(diff.hasReassignment, expectedReassign)

  // comparedSize = 至少一侧覆盖的报文数
  const coveredTotal = Object.values(catCount).reduce((s, n) => s + n, 0)
  assert.equal(diff.comparedSize, coveredTotal)

  rounds++
}
console.log(`快照对比模糊对照 ${rounds} 轮全部通过 ✔`)
