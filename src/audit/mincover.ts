/**
 * 最小解释集的精确集合覆盖求解。
 *
 * 给定 n 个候选（n ≤ EXACT_LIMIT），每个候选由一个 BigInt 位掩码描述其
 * 覆盖的单元；找出掩码并集等于全集 totalMask 的基数最小候选子集，
 * 同基数时按**候选下标数组字典序**取唯一结果。
 *
 * 这里不使用贪心：贪心只给近似解，可能漏掉更优的小基数集合。
 * 实现按基数 k = 1..n 递增枚举候选下标组合（每组按下标升序生成，
 * 天然字典序），第一个覆盖全集的组合即唯一最优答案。
 */

/** 候选来源数不超过该上限时必须精确求解；超过则调用方应明确提示“不计算” */
export const MIN_EXPLANATION_EXACT_LIMIT = 18

/** 位掩码中置位个数 */
export function popCount(mask: bigint): number {
  let x = mask
  let n = 0
  while (x > 0n) {
    x &= x - 1n
    n++
  }
  return n
}

/**
 * 精确最小集合覆盖。
 * @param masks 候选掩码（顺序即规则序号顺序）；空掩码候选不影响结果
 * @param totalMask 必须被完全覆盖的单元全集
 * @returns 入选候选的下标（升序）；并集无法覆盖全集时返回 null
 */
export function minimumCover(masks: bigint[], totalMask: bigint): number[] | null {
  const n = masks.length
  // 后缀并集：dfs 中用于判定“剩余候选是否还可能补齐缺口”，安全剪枝
  const suffixUnion = new Array<bigint>(n + 1)
  suffixUnion[n] = 0n
  for (let i = n - 1; i >= 0; i--) suffixUnion[i] = suffixUnion[i + 1] | masks[i]

  const chosen: number[] = []

  function dfs(start: number, covered: bigint, remaining: number): boolean {
    if (covered === totalMask) return true
    if (remaining === 0) return false
    // 即使把 start 之后的全部候选都选上也补不齐缺口 → 此路不通
    if ((covered | suffixUnion[start]) !== totalMask) return false
    for (let i = start; i <= n - remaining; i++) {
      chosen.push(i)
      if (dfs(i + 1, covered | masks[i], remaining - 1)) return true
      chosen.pop()
    }
    return false
  }

  if ((suffixUnion[0] & totalMask) !== totalMask) return null
  // 按基数递增；同基数组合按下标升序枚举 → 首个命中即“最小 + 字典序最小”
  for (let k = 1; k <= n; k++) {
    if (dfs(0, 0n, k)) return [...chosen]
  }
  return null
}
