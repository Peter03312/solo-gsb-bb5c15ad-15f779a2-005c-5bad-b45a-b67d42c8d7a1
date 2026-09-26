/** 数字与报文展示辅助 */

export function formatSize(n: number): string {
  if (n === 0) return '0'
  return n.toLocaleString('en-US')
}

export function formatPercent(ratio: number): string {
  if (ratio >= 0.99995 && ratio <= 1.00005) return '100%'
  return `${(ratio * 100).toFixed(2)}%`
}

export function formatPortRange(start: number, end: number): string {
  return start === end ? String(start) : `${start}–${end}`
}

/** 示例报文的可复现单行表示，可直接粘贴复现 */
export function formatPacket(p: {
  srcIp: string
  srcPort: number
  protocol: string
}): string {
  return `${p.protocol} src=${p.srcIp}:${p.srcPort}`
}
