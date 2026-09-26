/**
 * IPv4 / CIDR 工具。
 * 解析与规范化使用 ipaddr.js；数值运算自行处理为 32 位无符号整数。
 */
import ipaddr from 'ipaddr.js'

export interface ParsedCidr {
  start: number
  end: number
  prefix: number
  canonical: string
}

/** 点分十进制 -> uint32 */
export function ipv4ToInt(text: string): number {
  const addr = ipaddr.parse(text)
  if (addr.kind() !== 'ipv4') throw new Error('仅支持 IPv4')
  const octets = (addr as ipaddr.IPv4).octets
  return (
    ((octets[0] << 24) >>> 0) +
    ((octets[1] << 16) >>> 0) +
    (octets[2] << 8) +
    octets[3]
  )
}

/** uint32 -> 点分十进制 */
export function intToIpv4(value: number): string {
  const v = value >>> 0
  return `${(v >>> 24) & 0xff}.${(v >>> 16) & 0xff}.${(v >>> 8) & 0xff}.${v & 0xff}`
}

/**
 * 严格解析 IPv4 CIDR。
 * 拒绝条件：格式错误、非 IPv4、前缀越界、主机位非零（非规范写法）。
 */
export function parseCidrStrict(raw: string): ParsedCidr {
  const text = raw.trim()
  const parts = text.split('/')
  if (parts.length !== 2) {
    throw new Error('CIDR 必须形如 10.0.0.0/8')
  }
  let addr: ipaddr.IPv4
  const ipText = parts[0].trim()
  // ipaddr.js v2 会把 10.0.0 当作 10.0.0.0 的缩写，这里要求严格四段式
  const octetTexts = ipText.split('.')
  if (
    octetTexts.length !== 4 ||
    !octetTexts.every((o) => /^\d+$/.test(o) && Number(o) >= 0 && Number(o) <= 255)
  ) {
    throw new Error('IP 地址必须为点分十进制四段，每段 0-255')
  }
  try {
    const parsed = ipaddr.parse(ipText)
    if (parsed.kind() !== 'ipv4') throw new Error('仅支持 IPv4')
    addr = parsed as ipaddr.IPv4
  } catch (err) {
    throw new Error(`IP 地址非法：${(err as Error).message}`)
  }

  if (!/^\d+$/.test(parts[1].trim())) {
    throw new Error('前缀长度必须为 0-32 的整数')
  }
  const prefix = Number(parts[1].trim())
  if (prefix < 0 || prefix > 32) {
    throw new Error('前缀长度必须在 0-32 之间')
  }

  const addrInt = ipv4ToInt(addr.toString())
  // ipaddr.js v2 移除了 mask()，直接按位与得到网络地址
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const start = (addrInt & mask) >>> 0
  const networkText = intToIpv4(start)
  if (networkText !== addr.toString()) {
    throw new Error(`主机位非零，规范写法应为 ${networkText}/${prefix}`)
  }

  const size = prefix === 32 ? 1 : 2 ** (32 - prefix)
  const end = (start + size - 1) >>> 0
  return { start, end, prefix, canonical: `${networkText}/${prefix}` }
}

/**
 * 严格解析点分十进制 IPv4 地址（流量样本等场景的具体地址，非 CIDR）。
 * 与 parseCidrStrict 同样拒绝缩写写法（ipaddr.js 会把 10.0.0 当作 10.0.0.0），
 * 要求严格的四段十进制；返回 uint32 与规范化文本（去掉前导零）。
 */
export function parseIpv4Strict(raw: string): { ip: number; canonical: string } {
  const text = raw.trim()
  const octets = text.split('.')
  if (
    octets.length !== 4 ||
    !octets.every((o) => /^\d+$/.test(o) && Number(o) <= 255)
  ) {
    throw new Error('IP 地址必须为点分十进制四段，每段 0-255')
  }
  const ip =
    ((Number(octets[0]) << 24) >>> 0) +
    (Number(octets[1]) << 16) +
    (Number(octets[2]) << 8) +
    Number(octets[3])
  return { ip, canonical: intToIpv4(ip) }
}

/**
 * 若 ip 是给定块中取第 offset 个地址（offset 可为负，-1 表示最后一个）。
 */
export function ipInBlock(blockStart: number, blockSize: number, offset: number): number {
  if (offset < 0) offset = blockSize + offset
  return (blockStart + offset) >>> 0
}

/** 形如 255.255.255.255/32 */
export function formatCidr(start: number, prefix: number): string {
  return `${intToIpv4(start)}/${prefix}`
}
