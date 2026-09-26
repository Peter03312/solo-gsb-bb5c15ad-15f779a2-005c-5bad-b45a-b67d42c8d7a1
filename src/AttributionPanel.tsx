import { useRef, useState } from 'react'
import { attributeSamples } from './audit/attribution'
import type { AttributionGroup, AttributionResult } from './audit/attribution'
import type { RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

const EXAMPLE_JSON = `[
  { "id": "s1", "srcIp": "10.0.0.5", "srcPort": 8080, "protocol": "TCP", "weight": 3 },
  { "id": "s2", "srcIp": "192.168.1.20", "srcPort": 22, "protocol": "ANY", "weight": 1.5 },
  { "id": "s3", "srcIp": "203.0.113.9", "srcPort": 53, "protocol": "UDP", "weight": 0.5 }
]`

/** 单个汇总分组（命中某规则 / 未命中），可展开查看按权重降序的样本明细 */
function GroupEntry({
  group,
  unmatched,
  totalWeight,
}: {
  group: AttributionGroup
  unmatched: boolean
  totalWeight: number
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className={`entry ${unmatched ? 'entry-invalid' : ''} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        {unmatched ? (
          <span className="title">未命中任何规则</span>
        ) : (
          <>
            <span className="idx-cell">#{group.matchedRuleIndex! + 1}</span>
            <span className="title">{group.matchedRuleName}</span>
            <span className="action-pill">{group.action}</span>
          </>
        )}
        <span className="spacer" />
        <span className="meta">
          权重 {formatSize(group.weight)}（{formatPercent(group.ratio)}） ·{' '}
          {group.judgements.length} 条判定
        </span>
      </div>
      {open && (
        <div className="entry-body" onClick={(e) => e.stopPropagation()}>
          <div className="goal-block-title">样本明细（按权重降序）</div>
          {group.judgements.map((j, i) => (
            <div className="source-row" key={i}>
              <span className="idx-cell">第 {j.line} 条</span>
              <span className="mono attribution-sample-id">{j.id}</span>
              <span className="mono">{formatPacket(j)}</span>
              <span className="spacer" />
              <span className="muted-text">
                权重 {formatSize(j.weight)}（{formatPercent(totalWeight === 0 ? 0 : j.weight / totalWeight)}）
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ResultView({ result }: { result: AttributionResult }) {
  const groupCount = result.groups.length + (result.unmatched ? 1 : 0)
  return (
    <>
      <div className="legend simplify-summary">
        基于 {result.activeRuleCount} 条合法且启用的规则
        {result.invalidExcluded > 0 && `（${result.invalidExcluded} 条非法规则已排除）`}
        {result.disabledExcluded > 0 && `（${result.disabledExcluded} 条停用规则已排除）`}
        ：{result.sampleCount} 条合法样本产生 {result.judgementCount} 条判定
        {result.sampleCount !== result.judgementCount && '（ANY 样本按同一权重分别判定 TCP 与 UDP）'}
        {result.errors.length > 0 && `；${result.errors.length} 行错误未计入统计`}
      </div>

      <div className="stats">
        <div className="stat-card">
          <div className="label">合法样本 / 判定条数</div>
          <div className="value" style={{ fontSize: 16 }}>
            {result.sampleCount}
            <span className="muted-text"> / {result.judgementCount}</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="label">总权重</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.totalWeight)}
          </div>
        </div>
        <div className="stat-card ok">
          <div className="label">命中权重</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.matchedWeight)}
          </div>
          <div className="label">{formatPercent(result.matchedRatio)}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">未命中权重</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.unmatchedWeight)}
          </div>
          <div className="label">{formatPercent(result.unmatchedRatio)}</div>
        </div>
      </div>

      {groupCount === 0 ? (
        <div className="notice info" style={{ marginBottom: 0 }}>
          没有可统计的合法样本。请检查粘贴的 JSON，或修正上方列出的错误行后重新执行。
        </div>
      ) : (
        <>
          <h3 className="reorder-section-title">
            归因分组（{groupCount} 组，按权重降序；未命中列于最后，点击展开样本明细）
          </h3>
          {result.groups.map((g) => (
            <GroupEntry key={g.key} group={g} unmatched={false} totalWeight={result.totalWeight} />
          ))}
          {result.unmatched && (
            <GroupEntry group={result.unmatched} unmatched totalWeight={result.totalWeight} />
          )}
        </>
      )}
    </>
  )
}

export function AttributionPanel({ rules }: Props) {
  const [text, setText] = useState('')
  const [result, setResult] = useState<AttributionResult | null>(null)
  // 执行时刻的规则 / 文本快照：规则编辑、调序、启停或文本改动都会使结果过期
  const rulesSnapshotRef = useRef<RuleInput[] | null>(null)
  const textSnapshotRef = useRef<string>('')
  const stale = result !== null && rulesSnapshotRef.current !== rules
  const dirty = result !== null && text !== textSnapshotRef.current

  const run = () => {
    setResult(attributeSamples(rules, text))
    rulesSnapshotRef.current = rules
    textSnapshotRef.current = text
  }

  return (
    <div className="panel attribution-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>流量样本归因</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          粘贴流量样本 JSON 数组，按当前规则的首命中语义逐条判定命中规则与动作，
          按权重汇总占比；ANY 样本按同一权重分别判定 TCP 与 UDP
        </span>
      </div>

      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={EXAMPLE_JSON}
        spellCheck={false}
      />
      <div className="attribution-actions">
        <button className="primary" onClick={run}>
          {result ? '重新执行归因' : '执行归因'}
        </button>
        <span className="legend" style={{ margin: 0 }}>
          字段：id（唯一）· srcIp · srcPort · protocol（TCP / UDP / ANY）· weight（正数）；
          重复 id 与非法字段逐行报错，错误行不计入统计
        </span>
      </div>

      {result && (
        <>
          {stale && (
            <div className="notice error">
              ⚠ 规则自上次归因后已被编辑、调序或启停，以下结果<strong>已过期</strong>。
              请点击「重新执行归因」刷新。
            </div>
          )}
          {dirty && !stale && (
            <div className="notice info">
              样本输入已修改，以下结果仍对应上次执行的样本；点击「重新执行归因」以新样本重新统计。
            </div>
          )}

          {result.errors.length > 0 && (
            <div className="notice error">
              <strong>{result.errors.length} 行有误（不计入统计）：</strong>
              {result.errors.map((e, i) => (
                <div key={i}>
                  • {e.line > 0 ? `第 ${e.line} 条` : '输入'}
                  {e.id !== null && <span className="mono">（id={e.id}）</span>}：
                  {e.errors.join('；')}
                </div>
              ))}
            </div>
          )}

          <ResultView result={result} />
        </>
      )}

      {!result && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          粘贴样本后点击「执行归因」。分析是只读的，不改动任何规则；
          非法 / 停用规则不参与判定（与审计语义一致）。
        </div>
      )}
    </div>
  )
}
