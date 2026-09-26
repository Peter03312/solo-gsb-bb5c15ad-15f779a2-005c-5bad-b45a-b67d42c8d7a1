import { useMemo, useState } from 'react'
import { verifyGoal } from './audit/verify'
import type {
  GoalActionGroup,
  GoalInput,
  GoalRegionGroup,
  GoalVerifyResult,
} from './audit/verify'
import type { RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
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
      {copied ? '已复制' : '复制'}
    </button>
  )
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR 列表（行式，互斥且完备） */
function RegionView({ regions }: { regions: GoalRegionGroup[] }) {
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} ×{' '}
              {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function ActionGroupCard({
  group,
  rank,
}: {
  group: GoalActionGroup
  rank: number
}) {
  return (
    <div className="traffic-card traffic-action-changed">
      <div className="traffic-flow">
        <span className="muted-text">违规 {rank} · 实际动作</span>
        <span className="action-pill">{group.action}</span>
        <span className="traffic-alert">命中其他动作</span>
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(group.size)} 条报文空间（{formatPercent(group.ratio)}）
        </span>
      </div>
      <div className="goal-block-title">代表报文（可复制复现）</div>
      {group.examples.map((p, i) => (
        <div className="packet-box" key={i}>
          <span className="tag shadowed">代表报文</span>
          <span>{formatPacket(p)}</span>
          <span className="arrow-note">
            → 命中 #{p.matchedRuleIndex + 1} {p.matchedRuleName}（{group.action}）
          </span>
          <CopyButton text={formatPacket(p)} />
        </div>
      ))}
      <div className="goal-block-title">精确区域（CIDR × 端口）</div>
      <RegionView regions={group.regions} />
    </div>
  )
}

function UnmatchedCard({ result }: { result: GoalVerifyResult }) {
  const u = result.unmatched!
  return (
    <div className="traffic-card traffic-action-changed">
      <div className="traffic-flow">
        <span className="muted-text">违规 · 目标报文不被任何规则覆盖</span>
        <span className="action-pill">未命中任何规则</span>
        <span className="traffic-alert">无规则覆盖</span>
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(u.size)} 条报文空间（{formatPercent(u.ratio)}）
        </span>
      </div>
      <div className="goal-block-title">代表报文（可复制复现）</div>
      {u.examples.map((p, i) => (
        <div className="packet-box" key={i}>
          <span className="tag shadowed">代表报文</span>
          <span>{formatPacket(p)}</span>
          <span className="arrow-note">→ 不被任何合法规则覆盖</span>
          <CopyButton text={formatPacket(p)} />
        </div>
      ))}
      <div className="goal-block-title">精确区域（CIDR × 端口）</div>
      <RegionView regions={u.regions} />
    </div>
  )
}

function GoalResultView({ result }: { result: GoalVerifyResult }) {
  const g = result.goal
  const allConform = result.otherActionSize === 0 && result.unmatchedSize === 0
  return (
    <div className="goal-result">
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        目标 <span className="mono">{g.cidrText}</span> · 端口{' '}
        {formatPortRange(g.portStart, g.portEnd)} · 协议 {g.protocol} · 期望动作{' '}
        <span className="action-pill">{g.expectedAction}</span> · 目标总空间{' '}
        {formatSize(result.totalSize)}；基于 {result.validRuleCount} 条合法且启用的规则
        {result.invalidExcluded > 0
          ? `（${result.invalidExcluded} 条非法规则已排除，不参与验证）`
          : ''}
        {result.disabledExcluded > 0
          ? `（${result.disabledExcluded} 条停用规则已排除，不参与验证）`
          : ''}
        。结果随规则编辑 / 调序确认自动刷新。
      </div>

      {allConform ? (
        <div className="notice ok">
          ✓ 目标空间全部符合期望：目标内每个报文的首命中动作都是「
          {g.expectedAction}」。
        </div>
      ) : (
        <div className="notice error">
          ✗ 目标未完全满足：命中其他动作 {formatSize(result.otherActionSize)}（
          {formatPercent(result.otherActionRatio)}），未命中任何规则{' '}
          {formatSize(result.unmatchedSize)}（{formatPercent(result.unmatchedRatio)}
          ）。违规明细见下方分组。
        </div>
      )}

      <div className="stats">
        <div className="stat-card ok">
          <div className="label">符合期望（{g.expectedAction}）</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.conformSize)}
          </div>
          <div className="label">{formatPercent(result.conformRatio)}</div>
        </div>
        <div className="stat-card warn">
          <div className="label">命中其他动作</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.otherActionSize)}
          </div>
          <div className="label">{formatPercent(result.otherActionRatio)}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">未命中任何规则</div>
          <div className="value" style={{ fontSize: 16 }}>
            {formatSize(result.unmatchedSize)}
          </div>
          <div className="label">{formatPercent(result.unmatchedRatio)}</div>
        </div>
      </div>

      {g.protocol === 'ANY' && (
        <div style={{ overflowX: 'auto', marginBottom: 12 }}>
          <table className="rule-table goal-proto-table">
            <thead>
              <tr>
                <th>协议（ANY 分别检查）</th>
                <th>符合期望</th>
                <th>命中其他动作</th>
                <th>未命中任何规则</th>
              </tr>
            </thead>
            <tbody>
              {result.perProtocol.map((p) => (
                <tr key={p.protocol}>
                  <td>{p.protocol}</td>
                  <td className="goal-num">{formatSize(p.conformSize)}</td>
                  <td className="goal-num">{formatSize(p.otherActionSize)}</td>
                  <td className="goal-num">{formatSize(p.unmatchedSize)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(result.actionGroups.length > 0 || result.unmatched) && (
        <h3 className="reorder-section-title">
          违规区域（按实际动作汇总，共{' '}
          {result.actionGroups.length + (result.unmatched ? 1 : 0)} 类）
        </h3>
      )}
      {result.actionGroups.map((group, i) => (
        <ActionGroupCard key={group.action} group={group} rank={i + 1} />
      ))}
      {result.unmatched && <UnmatchedCard result={result} />}
    </div>
  )
}

export function GoalVerify({ rules }: Props) {
  const [form, setForm] = useState<GoalInput>({
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    expectedAction: 'allow',
  })
  const [submitted, setSubmitted] = useState<GoalInput | null>(null)

  // 只读验证：纯函数计算，不改动规则；rules 变化（编辑 / 调序确认）时自动重算
  const outcome = useMemo(
    () => (submitted ? verifyGoal(rules, submitted) : null),
    [rules, submitted],
  )

  const dirty =
    submitted !== null &&
    (form.cidr !== submitted.cidr ||
      String(form.portStart) !== String(submitted.portStart) ||
      String(form.portEnd) !== String(submitted.portEnd) ||
      form.protocol !== submitted.protocol ||
      form.expectedAction !== submitted.expectedAction)

  const actionSuggestions = useMemo(
    () => [...new Set(rules.map((r) => r.action.trim()).filter(Boolean))],
    [rules],
  )

  const patch = (p: Partial<GoalInput>) => setForm((f) => ({ ...f, ...p }))

  return (
    <div className="panel goal-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>策略目标验证（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          输入目标空间与期望动作，按首条命中语义检查当前规则；不修改任何规则
        </span>
      </div>

      <div className="goal-form">
        <label>
          <span>目标 IPv4 CIDR</span>
          <input
            value={form.cidr}
            onChange={(e) => patch({ cidr: e.target.value })}
            placeholder="10.0.0.0/8"
            spellCheck={false}
          />
        </label>
        <label>
          <span>目标端口区间</span>
          <div className="port-cell">
            <input
              value={form.portStart}
              onChange={(e) => patch({ portStart: e.target.value })}
              placeholder="0"
            />
            <span className="muted-text">–</span>
            <input
              value={form.portEnd}
              onChange={(e) => patch({ portEnd: e.target.value })}
              placeholder="65535"
            />
          </div>
        </label>
        <label>
          <span>协议</span>
          <select
            value={form.protocol}
            onChange={(e) => patch({ protocol: e.target.value })}
          >
            {['ANY', 'TCP', 'UDP'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>期望动作</span>
          <input
            list="goal-action-options"
            value={form.expectedAction}
            onChange={(e) => patch({ expectedAction: e.target.value })}
            placeholder="allow / deny"
          />
        </label>
        <button className="primary" onClick={() => setSubmitted({ ...form })}>
          执行验证
        </button>
      </div>
      <datalist id="goal-action-options">
        {actionSuggestions.map((a) => (
          <option key={a} value={a} />
        ))}
      </datalist>

      {outcome && !outcome.ok && (
        <div className="notice error">
          {outcome.errors.map((e, i) => (
            <div key={i}>• {e}</div>
          ))}
        </div>
      )}

      {dirty && outcome?.ok && (
        <div className="notice info">
          目标输入已修改，以下结果仍对应上次验证的目标；点击「执行验证」以新目标重新验证。
        </div>
      )}

      {!submitted && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          填写目标后点击「执行验证」。非法规则会被排除；协议 ANY 将分别检查 TCP 与 UDP。
        </div>
      )}

      {outcome?.ok && <GoalResultView result={outcome.result} />}
    </div>
  )
}
