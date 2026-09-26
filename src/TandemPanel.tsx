import { useMemo, useState } from 'react'
import { evaluateTandem, TANDEM_CATEGORY_ORDER } from './audit/tandem'
import type {
  TandemCategory,
  TandemCategorySummary,
  TandemFormInput,
  TandemResult,
  TandemRuleRef,
  TandemTraceGroup,
} from './audit/tandem'
import { parseRulesJson, validateRules } from './audit/engine'
import type { ExactRegionGroup, RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

const CATEGORY_META: Record<
  TandemCategory,
  { label: string; badge: string; card: string }
> = {
  pass: { label: '最终通过', badge: 'reachable', card: 'ok' },
  'blocked-stage1': { label: '第一阶段阻断', badge: 'fully-shadowed', card: 'danger' },
  'blocked-stage2': { label: '第二阶段阻断', badge: 'partial-shadowed', card: 'warn' },
}

const EXAMPLE_STAGE2_JSON = `[
  { "name": "放行办公网", "cidr": "10.0.0.0/8", "portStart": 0, "portEnd": 65535,
    "protocol": "ANY", "action": "allow" },
  { "name": "默认拒绝", "cidr": "0.0.0.0/0", "portStart": 0, "portEnd": 65535,
    "protocol": "ANY", "action": "deny" }
]`

function CopyButton({ text }: { text: string }) {
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
      {copied ? '已复制' : '复制'}
    </button>
  )
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR（行式，互斥且完备） */
function RegionView({ regions }: { regions: ExactRegionGroup[] }) {
  if (regions.length === 0) {
    return <div className="muted-text" style={{ paddingLeft: 12 }}>（无区域）</div>
  }
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} × {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

/** 某一阶段的首命中规则引用 / 未命中 / 未进入该阶段 */
function StageRefView({
  stage,
  ref_,
  entered,
}: {
  stage: string
  ref_: TandemRuleRef | null
  entered: boolean
}) {
  if (!entered) {
    return <span className="action-pill conflict-pill">{stage}：未进入</span>
  }
  if (!ref_) {
    return <span className="action-pill conflict-pill">{stage}：未命中任何规则</span>
  }
  return (
    <span className="traffic-side">
      <span className="muted-text">{stage}</span>
      <span className="idx-cell">#{ref_.index + 1}</span>
      <span className="reorder-rule-name">{ref_.name}</span>
      <span className="action-pill">{ref_.action}</span>
    </span>
  )
}

/** 分组的判定理由（为什么阻断 / 通过） */
function groupReason(group: TandemTraceGroup): string {
  if (group.category === 'pass') return '两阶段首命中动作均在各自放行列表内 → 最终通过'
  if (group.category === 'blocked-stage1') {
    return group.stage1 === null
      ? '第一阶段未命中任何规则 → 阻断（未命中即阻断，不进入第二阶段）'
      : `第一阶段首命中动作「${group.stage1.action}」不在放行列表内 → 阻断（不进入第二阶段）`
  }
  return group.stage2 === null
    ? '第二阶段未命中任何规则 → 阻断'
    : `第二阶段首命中动作「${group.stage2.action}」不在放行列表内 → 阻断`
}

/** 一条分阶段命中轨迹分组卡片 */
function TraceGroupCard({ group }: { group: TandemTraceGroup }) {
  const meta = CATEGORY_META[group.category]
  return (
    <div className={`takeover-block ${group.category === 'pass' ? '' : 'conflict-block'}`}>
      <div className="takeover-head">
        <span className={`badge ${meta.badge}`}>{meta.label}</span>
        <StageRefView stage="第一阶段" ref_={group.stage1} entered />
        <span className="reorder-arrow">→</span>
        <StageRefView stage="第二阶段" ref_={group.stage2} entered={group.enteredStage2} />
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(group.size)} 条报文空间（{group.cells} 个原子单元）
        </span>
      </div>
      <div className="packet-box">
        <span className="tag shadowed">代表报文</span>
        <span className="mono">{formatPacket(group.packet)}</span>
        <span className="arrow-note">{groupReason(group)}</span>
        <CopyButton text={formatPacket(group.packet)} />
      </div>
      <RegionView regions={group.regions} />
    </div>
  )
}

/** 一个类别的完整小节：汇总 + 带轨迹的代表报文 + 精确区域 + 轨迹分组 */
function CategorySection({ summary }: { summary: TandemCategorySummary }) {
  const meta = CATEGORY_META[summary.category]
  return (
    <div className="snapshot-category">
      <h3 className="reorder-section-title" style={{ marginTop: 14 }}>
        <span className={`badge ${meta.badge}`}>{meta.label}</span>{' '}
        <span className="muted-text" style={{ fontWeight: 400 }}>
          {formatSize(summary.size)} 条报文空间（{formatPercent(summary.ratio)}） ·{' '}
          {summary.cells} 个原子单元
        </span>
      </h3>

      <div className="goal-block-title">代表报文（每个具体协议一个，附分阶段命中轨迹，可复制复现）</div>
      {summary.examples.map((p, i) => (
        <div className="packet-box" key={i}>
          <span className="tag shadowed">代表报文</span>
          <span className="mono">{formatPacket(p)}</span>
          <span className="arrow-note">
            第一阶段：
            {p.stage1 ? `#${p.stage1.index + 1} ${p.stage1.name}（${p.stage1.action}）` : '未命中'}
            {' → '}
            {p.enteredStage2
              ? `第二阶段：${p.stage2 ? `#${p.stage2.index + 1} ${p.stage2.name}（${p.stage2.action}）` : '未命中'}`
              : '未进入第二阶段'}
          </span>
          <CopyButton text={formatPacket(p)} />
        </div>
      ))}

      <div className="goal-block-title">精确区域（协议 → 连续端口段 × 规范 CIDR）</div>
      <RegionView regions={summary.regions} />

      <div className="goal-block-title">
        分阶段命中轨迹分组（同一组内每个报文的两阶段首命中轨迹相同，共 {summary.groups.length} 组）
      </div>
      {summary.groups.map((g, i) => (
        <TraceGroupCard key={i} group={g} />
      ))}
    </div>
  )
}

function TandemResultView({ result }: { result: TandemResult }) {
  const cats = result.categories
  const t = result.target
  const allPass = cats['blocked-stage1'].cells === 0 && cats['blocked-stage2'].cells === 0
  const stageSummary = (label: string, s: TandemResult['stage1'], allow: string[]) => (
    <>
      {label}：{s.active} 条合法且启用的规则参与重放
      {s.invalid > 0 ? `，${s.invalid} 条非法已排除` : ''}
      {s.disabled > 0 ? `，${s.disabled} 条停用已排除` : ''}
      ；放行动作 = {allow.map((a) => (
        <span key={a} className="action-pill" style={{ marginRight: 4 }}>
          {a}
        </span>
      ))}
    </>
  )

  return (
    <div className="snapshot-report">
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        目标 <span className="mono">{t.cidrText}</span> · 端口{' '}
        {formatPortRange(t.portStart, t.portEnd)} · 协议 {t.protocol} · 目标总空间{' '}
        {formatSize(result.totalSize)}。
        {stageSummary('第一阶段（当前规则）', result.stage1, result.allow1)}
        <br />
        {stageSummary('第二阶段（粘贴规则）', result.stage2, result.allow2)}
        。目标与双方规则边界已合并切分，逐单元串联重放（报文不改写）；
        结果随当前规则编辑 / 调序确认自动刷新。
      </div>

      {allPass ? (
        <div className="notice ok">
          ✓ 目标空间全部最终通过：每个报文在两个阶段的首命中动作都在各自放行列表内。
        </div>
      ) : (
        <div className="notice error">
          ✗ 目标未全部通过：第一阶段阻断 {formatSize(cats['blocked-stage1'].size)}（
          {formatPercent(cats['blocked-stage1'].ratio)}），第二阶段阻断{' '}
          {formatSize(cats['blocked-stage2'].size)}（
          {formatPercent(cats['blocked-stage2'].ratio)}）。明细见下方分类。
        </div>
      )}

      <div className="stats">
        {TANDEM_CATEGORY_ORDER.map((c) => (
          <div className={`stat-card ${CATEGORY_META[c].card}`} key={c}>
            <div className="label">{CATEGORY_META[c].label}</div>
            <div className="value" style={{ fontSize: 16 }}>
              {formatSize(cats[c].size)}
            </div>
            <div className="label">
              {formatPercent(cats[c].ratio)} · {cats[c].cells} 个原子单元
            </div>
          </div>
        ))}
      </div>

      {t.protocol === 'ANY' && (
        <div style={{ overflowX: 'auto', marginBottom: 12 }}>
          <table className="rule-table goal-proto-table">
            <thead>
              <tr>
                <th>协议（ANY 分别重放）</th>
                <th>最终通过</th>
                <th>第一阶段阻断</th>
                <th>第二阶段阻断</th>
              </tr>
            </thead>
            <tbody>
              {result.perProtocol.map((p) => (
                <tr key={p.protocol}>
                  <td>{p.protocol}</td>
                  <td className="goal-num">{formatSize(p.passSize)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage1Size)}</td>
                  <td className="goal-num">{formatSize(p.blockedStage2Size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {TANDEM_CATEGORY_ORDER.filter((c) => cats[c].cells > 0).map((c) => (
        <CategorySection key={c} summary={cats[c]} />
      ))}
    </div>
  )
}

export function TandemPanel({ rules }: Props) {
  const [stage2Json, setStage2Json] = useState('')
  const [allow1Text, setAllow1Text] = useState('allow')
  const [allow2Text, setAllow2Text] = useState('allow')
  const [targetForm, setTargetForm] = useState({
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
  })
  const [submitted, setSubmitted] = useState<TandemFormInput | null>(null)

  const form: TandemFormInput = {
    stage2Json,
    allow1Text,
    allow2Text,
    target: targetForm,
  }

  // 只读分析：纯函数计算，不改动任何规则；当前规则编辑 / 调序确认后自动重算
  const outcome = useMemo(
    () => (submitted ? evaluateTandem(rules, submitted) : null),
    [rules, submitted],
  )

  const dirty =
    submitted !== null &&
    (form.stage2Json !== submitted.stage2Json ||
      form.allow1Text !== submitted.allow1Text ||
      form.allow2Text !== submitted.allow2Text ||
      form.target.cidr !== submitted.target.cidr ||
      String(form.target.portStart) !== String(submitted.target.portStart) ||
      String(form.target.portEnd) !== String(submitted.target.portEnd) ||
      form.target.protocol !== submitted.target.protocol)

  // 动作建议：第一阶段取当前规则动作；第二阶段实时宽容解析粘贴的 JSON（仅用于输入建议）
  const stage1Actions = useMemo(
    () => [...new Set(rules.map((r) => r.action.trim()).filter(Boolean))],
    [rules],
  )
  const stage2Actions = useMemo(() => {
    if (!stage2Json.trim()) return []
    const { rules: parsed, errors } = parseRulesJson(stage2Json)
    if (errors.length > 0) return []
    return [...new Set(parsed.map((r) => r.action.trim()).filter(Boolean))]
  }, [stage2Json])

  // 第一阶段规则构成提示（与分析同一套语义：合法且启用才参与）
  const stage1Stats = useMemo(() => {
    const { valid, invalid } = validateRules(rules)
    const disabled = valid.filter((r) => !r.enabled).length
    return { active: valid.length - disabled, invalid: invalid.length, disabled }
  }, [rules])

  const submit = () =>
    setSubmitted({
      stage2Json,
      allow1Text,
      allow2Text,
      target: { ...targetForm },
    })

  return (
    <div className="panel tandem-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>双级串联策略（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          当前规则为第一阶段，粘贴同格式 JSON 规则作为第二阶段；逐单元串联重放，
          每阶段仅首命中动作在其放行列表内才继续（未命中也阻断）；不修改任何规则
        </span>
      </div>

      <div className="tandem-stage-grid">
        <div className="tandem-stage-block">
          <div className="goal-block-title" style={{ marginTop: 0 }}>
            第一阶段：当前规则（{stage1Stats.active} 条合法启用参与重放
            {stage1Stats.invalid > 0 ? `，${stage1Stats.invalid} 条非法已排除` : ''}
            {stage1Stats.disabled > 0 ? `，${stage1Stats.disabled} 条停用已排除` : ''}）
          </div>
          <label>
            <span>第一阶段放行动作列表（逗号 / 空格分隔，精确匹配）</span>
            <input
              list="tandem-allow1-options"
              value={allow1Text}
              onChange={(e) => setAllow1Text(e.target.value)}
              placeholder="allow, permit"
              spellCheck={false}
            />
          </label>
          <datalist id="tandem-allow1-options">
            {stage1Actions.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
        </div>

        <div className="tandem-stage-block">
          <div className="goal-block-title" style={{ marginTop: 0 }}>
            第二阶段：粘贴同格式 JSON 规则（非法 / 停用规则按现有语义排除）
          </div>
          <textarea
            value={stage2Json}
            onChange={(e) => setStage2Json(e.target.value)}
            placeholder={EXAMPLE_STAGE2_JSON}
            spellCheck={false}
          />
          <label>
            <span>第二阶段放行动作列表（逗号 / 空格分隔，精确匹配）</span>
            <input
              list="tandem-allow2-options"
              value={allow2Text}
              onChange={(e) => setAllow2Text(e.target.value)}
              placeholder="allow, permit"
              spellCheck={false}
            />
          </label>
          <datalist id="tandem-allow2-options">
            {stage2Actions.map((a) => (
              <option key={a} value={a} />
            ))}
          </datalist>
        </div>
      </div>

      <div className="goal-form tandem-target-form">
        <label>
          <span>目标 IPv4 CIDR</span>
          <input
            value={targetForm.cidr}
            onChange={(e) => setTargetForm((f) => ({ ...f, cidr: e.target.value }))}
            placeholder="10.0.0.0/8"
            spellCheck={false}
          />
        </label>
        <label>
          <span>目标端口区间</span>
          <div className="port-cell">
            <input
              value={targetForm.portStart}
              onChange={(e) => setTargetForm((f) => ({ ...f, portStart: e.target.value }))}
              placeholder="0"
            />
            <span className="muted-text">–</span>
            <input
              value={targetForm.portEnd}
              onChange={(e) => setTargetForm((f) => ({ ...f, portEnd: e.target.value }))}
              placeholder="65535"
            />
          </div>
        </label>
        <label>
          <span>协议</span>
          <select
            value={targetForm.protocol}
            onChange={(e) => setTargetForm((f) => ({ ...f, protocol: e.target.value }))}
          >
            {['ANY', 'TCP', 'UDP'].map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </label>
        <button className="primary" onClick={submit}>
          执行分析
        </button>
      </div>

      {outcome && !outcome.ok && (
        <div className="notice error">
          <div style={{ fontWeight: 600, marginBottom: 4 }}>输入有误，已阻止分析：</div>
          {outcome.errors.map((e, i) => (
            <div key={i}>• {e}</div>
          ))}
        </div>
      )}

      {dirty && outcome?.ok && (
        <div className="notice info">
          输入已修改，以下结果仍对应上次分析；点击「执行分析」以新输入重新分析。
        </div>
      )}

      {!submitted && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          粘贴第二阶段规则 JSON、填写两阶段放行动作列表与目标空间后点击「执行分析」。
          目标与双方规则边界将合并切分后逐单元重放；协议 ANY 将分别检查 TCP 与 UDP。
        </div>
      )}

      {outcome?.ok && <TandemResultView result={outcome.result} />}
    </div>
  )
}
