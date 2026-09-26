import { useMemo, useRef, useState } from 'react'
import { exportRegression, generateRegressionSamples } from './audit/regression'
import type { RegressionGoal, RegressionResult, RegressionSample } from './audit/regression'
import type { RuleInput } from './audit/types'
import { formatPacket } from './format'

interface Props {
  rules: RuleInput[]
}

function CopyButton({ text, label = '复制' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      className="copy-mini"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          setCopied(false)
        }
      }}
    >
      {copied ? '已复制' : label}
    </button>
  )
}

function GoalChip({ goal }: { goal: RegressionGoal }) {
  return (
    <span className={`goal-chip ${goal.kind === 'block' ? 'goal-chip-block' : ''}`}>
      {goal.kind === 'first-hit' ? '首命中' : '阻挡见证'} #{goal.hitterRuleIndex + 1}{' '}
      {goal.hitterRuleName}
      {goal.kind === 'block' && (
        <>
          {' '}
          → #{goal.blockedRuleIndex! + 1} {goal.blockedRuleName}
        </>
      )}
    </span>
  )
}

function SampleCard({
  sample,
  rank,
  goalsById,
}: {
  sample: RegressionSample
  rank: number
  goalsById: Map<string, RegressionGoal>
}) {
  const goals = sample.coveredGoalIds
    .map((id) => goalsById.get(id))
    .filter((g): g is RegressionGoal => g !== undefined)
  return (
    <div className="takeover-block regression-sample">
      <div className="takeover-head">
        <span className="idx-cell">样例 #{rank}</span>
        <span className="mono">{formatPacket(sample.packet)}</span>
        <CopyButton text={formatPacket(sample.packet)} label="复制报文" />
        <span className="spacer" />
        <span className="muted-text">覆盖 {sample.coveredGoalIds.length} 个目标</span>
      </div>
      <div className="regression-expect">
        预期命中 <span className="idx-cell">#{sample.matchedRuleIndex + 1}</span>{' '}
        <span className="reorder-rule-name">{sample.matchedRuleName}</span> · 动作{' '}
        <span className="action-pill">{sample.action}</span>
      </div>
      <div className="goal-chip-list">
        {goals.map((g) => (
          <GoalChip key={g.id} goal={g} />
        ))}
      </div>
    </div>
  )
}

export function RegressionPanel({ rules }: Props) {
  const [result, setResult] = useState<RegressionResult | null>(null)
  const [goalsOpen, setGoalsOpen] = useState(false)
  const [jsonCopied, setJsonCopied] = useState(false)
  // 生成时刻的规则快照引用：规则编辑 / 调序 / 启停都会产生新数组，据此判定过期
  const snapshotRef = useRef<RuleInput[] | null>(null)
  const stale = result !== null && snapshotRef.current !== rules

  const goalsById = useMemo(
    () => new Map((result?.goals ?? []).map((g) => [g.id, g])),
    [result],
  )
  const exportJson = useMemo(() => (result ? exportRegression(result) : ''), [result])

  const run = () => {
    setResult(generateRegressionSamples(rules))
    snapshotRef.current = rules
    setGoalsOpen(false)
    setJsonCopied(false)
  }

  const download = () => {
    const blob = new Blob([exportJson], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `regression-samples-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="panel regression-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>策略回归样例生成器</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          基于当前合法且启用规则的同一原子空间，为「每条实际可达规则的首命中」与
          「每组首命中规则阻挡后续规则的关系」生成紧凑的回归报文集；一个报文可同时覆盖多个目标
        </span>
        <div style={{ flex: 1 }} />
        <button className="primary" onClick={run}>
          {result ? '重新生成' : '生成样例集'}
        </button>
      </div>

      {!result && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          点击「生成样例集」：按确定性贪心（未覆盖目标数最多优先，再按协议 / IP / 端口升序）
          挑选报文，直到每条实际可达规则至少被首命中一次、每组阻挡关系至少被见证一次。
          生成是只读的，不改动任何规则。
        </div>
      )}

      {result && (
        <>
          {stale && (
            <div className="notice error">
              ⚠ 规则自上次生成后已被编辑、调序或启停，以下样例集<strong>已过期</strong>：
              复制与下载已禁用。请点击「重新生成」后再导出。
            </div>
          )}

          {result.activeRuleCount === 0 ? (
            <div className="notice error" style={{ marginBottom: 0 }}>
              没有合法且启用的规则，无法生成回归样例。请新增规则、修正非法规则，
              或勾选「启用」后重新生成。
            </div>
          ) : (
            <>
              <div className="legend simplify-summary">
                基于 {result.activeRuleCount} 条合法且启用的规则（
                {result.reachableRuleCount} 条实际可达）：覆盖目标 {result.goalCount} 个（首命中{' '}
                {result.firstHitGoalCount} · 阻挡见证 {result.blockGoalCount}），
                <span className="safe-text">
                  {' '}
                  样例 {result.samples.length} 条，覆盖 {result.coveredGoalCount}/
                  {result.goalCount} 个目标
                </span>
              </div>

              <div className="regression-export-row">
                <button
                  disabled={stale}
                  title={stale ? '结果已过期，请重新生成' : '复制样例集 JSON'}
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(exportJson)
                      setJsonCopied(true)
                      setTimeout(() => setJsonCopied(false), 1500)
                    } catch {
                      setJsonCopied(false)
                    }
                  }}
                >
                  {jsonCopied ? '已复制到剪贴板' : '复制 JSON'}
                </button>
                <button
                  disabled={stale}
                  title={stale ? '结果已过期，请重新生成' : '下载样例集 JSON'}
                  onClick={download}
                >
                  下载 JSON
                </button>
                {stale && (
                  <span className="muted-text">旧结果已过期，重新生成后才可导出</span>
                )}
              </div>

              <h3 className="reorder-section-title">
                回归样例（{result.samples.length} 条，按生成顺序）
              </h3>
              {result.samples.map((sample, i) => (
                <SampleCard
                  key={i}
                  sample={sample}
                  rank={i + 1}
                  goalsById={goalsById}
                />
              ))}

              <div className={`entry regression-goals-entry ${goalsOpen ? 'open' : ''}`}>
                <div className="entry-header" onClick={() => setGoalsOpen((v) => !v)}>
                  <span className="chevron">▶</span>
                  <span className="title">覆盖目标清单（{result.goalCount}）</span>
                  <span className="spacer" />
                  <span className="meta">
                    {result.coveredGoalCount === result.goalCount
                      ? '全部目标均被覆盖'
                      : `${result.goalCount - result.coveredGoalCount} 个目标未覆盖`}
                  </span>
                </div>
                {goalsOpen && (
                  <div className="entry-body" onClick={(e) => e.stopPropagation()}>
                    {result.goals.map((g) => (
                      <div className="source-row" key={g.id}>
                        <span className={`goal-chip ${g.kind === 'block' ? 'goal-chip-block' : ''}`}>
                          {g.kind === 'first-hit' ? '首命中' : '阻挡见证'}
                        </span>
                        <span>{g.description.replace(/^(首命中|阻挡见证) /, '')}</span>
                        <span className="spacer" />
                        <span className="muted-text">
                          {g.coveredBy >= 0 ? `样例 #${g.coveredBy + 1}` : '未覆盖'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
