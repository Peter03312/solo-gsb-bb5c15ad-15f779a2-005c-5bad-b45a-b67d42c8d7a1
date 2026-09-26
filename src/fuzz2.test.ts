import assert from 'node:assert'
import { audit } from './audit/engine'
import type { RuleInput } from './audit/types'
import { intToIpv4, parseCidrStrict } from './audit/iputil'

function rand(n: number) { return Math.floor(Math.random() * n) }

// 在 10.0.0.0/8 内随机取前缀 8..16 的对齐 CIDR
function randomCidr() {
  const prefix = 8 + rand(9)
  const size = 2 ** (32 - prefix)
  const base = parseCidrStrict('10.0.0.0/8').start
  const count = 2 ** (prefix - 8)
  const start = (base + rand(count) * size) >>> 0
  return `${intToIpv4(start)}/${prefix}`
}
const PROTOS = ['TCP', 'UDP', 'ANY']
function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const a = rand(32), b = a + rand(32 - a)
    return {
      id: `g${i}`, name: `R${i}`, cidr: randomCidr(),
      portStart: String(a), portEnd: String(b),
      protocol: PROTOS[rand(3)], action: 'x', enabled: true,
    }
  })
}

/**
 * 无偏采样：规则 CIDR 全部 /16 对齐或更粗，因此对 10.x.0.0（x=0..255）
 * 每个 /16 取一个代表地址；端口 0..31、协议 2 个全枚举。
 * 每个采样点代表 65536 个真实 IP，声明/有效比值与全量精确一致。
 */
function bruteRatio(rules: RuleInput[]) {
  const parsed = rules.map((r) => ({
    c: parseCidrStrict(r.cidr),
    ps: Number(r.portStart), pe: Number(r.portEnd), p: r.protocol,
  }))
  const total = new Array(parsed.length).fill(0)
  const owned = new Array(parsed.length).fill(0)
  const base = parseCidrStrict('10.0.0.0/8').start
  for (let sub = 0; sub < 256; sub++) {
    const ipNum = (base + sub * 65536) >>> 0 // 10.sub.0.0
    for (let port = 0; port < 32; port++) {
      for (let pi = 0; pi < 2; pi++) {
        const p = pi === 0 ? 'TCP' : 'UDP'
        let first = -1
        for (let k = 0; k < parsed.length; k++) {
          const r = parsed[k]
          if (ipNum >= r.c.start && ipNum <= r.c.end &&
              port >= r.ps && port <= r.pe &&
              (r.p === 'ANY' || r.p === p)) {
            total[k]++
            if (first === -1) { first = k; owned[k]++ }
          }
        }
      }
    }
  }
  return parsed.map((_, k) => (total[k] === 0 ? 0 : owned[k] / total[k]))
}

let rounds = 0
for (let round = 0; round < 300; round++) {
  const rules = makeRules(1 + rand(8))
  const report = audit(rules)
  const ratios = bruteRatio(rules)
  for (const e of report.entries) {
    if (e.kind !== 'valid') continue
    assert.ok(Math.abs(e.effectiveRatio - ratios[e.index]) < 1e-9,
      `round ${round} rule ${e.index}: ratio ${e.effectiveRatio} vs brute ${ratios[e.index]}; ${JSON.stringify(rules)}`)
  }
  rounds++
}
console.log(`跨网段无偏模糊对照 ${rounds} 轮全部通过 ✔`)
