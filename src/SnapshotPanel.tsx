import { useEffect, useState } from 'react'
import {
  compareSnapshots,
  createSnapshot,
  loadSnapshots,
  persistSnapshots,
  snapshotRuleStats,
  DIFF_CATEGORY_ORDER,
} from './audit/snapshot'
import type {
  DiffCategory,
  DiffCategorySummary,
  DiffGroup,
  RuleSnapshot,
  SnapshotDiffResult,
} from './audit/snapshot'
import type { ExactRegionGroup, RuleInput } from './audit/types'
import { formatPacket, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
}

const CATEGORY_META: Record<
  DiffCategory,
  { label: string; badge: string; card: string }
> = {
  unchanged: { label: '动作未变', badge: 'reachable', card: 'ok' },
  'action-changed': { label: '动作改变', badge: 'fully-shadowed', card: 'danger' },
  'became-unmatched': { label: '由命中变为未命中', badge: 'partial-shadowed', card: 'warn' },
  'became-matched': { label: '由未命中变为命中', badge: 'info-badge', card: '' },
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('zh-CN', { hour12: false })
}

function CopyButton({ text, label = '复制报文' }: { text: string; label?: string }) {
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

function RuleRefView({ ref_ }: { ref_: DiffGroup['before'] }) {
  if (!ref_) {
    return <span className="action-pill conflict-pill">未命中任何规则</span>
  }
  return (
    <span className="traffic-side">
      <span className="idx-cell">#{ref_.index + 1}</span>
      <span className="reorder-rule-name">{ref_.name}</span>
      <span className="action-pill">{ref_.action}</span>
    </span>
  )
}

/** 一个下钻分组卡片：前后命中规则 / 未命中 → 代表报文 → 精确区域 */
function GroupCard({ group }: { group: DiffGroup }) {
  const meta = CATEGORY_META[group.category]
  return (
    <div
      className={`takeover-block ${
        group.category === 'unchanged' ? '' : 'conflict-block'
      }`}
    >
      <div className="takeover-head">
        <span className={`badge ${meta.badge}`}>{meta.label}</span>
        <RuleRefView ref_={group.before} />
        <span className="reorder-arrow">→</span>
        <RuleRefView ref_={group.after} />
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(group.size)} 条报文空间（{group.cells} 个原子单元）
        </span>
      </div>
      <div className="packet-box">
        <span className="tag shadowed">代表报文</span>
        <span className="mono">{formatPacket(group.packet)}</span>
        <span className="arrow-note">
          {group.before ? `旧：${group.before.action}` : '旧：未命中'} →{' '}
          {group.after ? `新：${group.after.action}` : '新：未命中'}
        </span>
        <CopyButton text={formatPacket(group.packet)} />
      </div>
      <RegionView regions={group.regions} />
    </div>
  )
}

/** 一个类别的完整小节：汇总 + 代表报文 + 精确区域 + 下钻分组 */
function CategorySection({ summary }: { summary: DiffCategorySummary }) {
  const meta = CATEGORY_META[summary.category]
  return (
    <div className="snapshot-category">
      <h3 className="reorder-section-title" style={{ marginTop: 14 }}>
        <span className={`badge ${meta.badge}`}>{meta.label}</span>{' '}
        <span className="muted-text" style={{ fontWeight: 400 }}>
          {formatSize(summary.size)} 条报文空间 · {summary.cells} 个原子单元
        </span>
      </h3>

      <div className="goal-block-title">代表报文（每个具体协议一个，可复制复现）</div>
      {summary.examples.map((p, i) => (
        <div className="packet-box" key={i}>
          <span className="tag shadowed">代表报文</span>
          <span className="mono">{formatPacket(p)}</span>
          <CopyButton text={formatPacket(p)} />
        </div>
      ))}

      <div className="goal-block-title">精确区域（协议 → 连续端口段 × 规范 CIDR）</div>
      <RegionView regions={summary.regions} />

      {summary.category === 'unchanged' ? (
        summary.groups.length > 0 ? (
          <>
            <div className="goal-block-title">
              同动作易主分组（动作未变，仅首命中规则改变，共 {summary.groups.length} 组）
            </div>
            {summary.groups.map((g, i) => (
              <GroupCard key={i} group={g} />
            ))}
          </>
        ) : (
          <div className="muted-text" style={{ marginTop: 8 }}>
            该类别内所有单元的首命中规则与动作均未变化。
          </div>
        )
      ) : (
        <>
          <div className="goal-block-title">
            下钻分组（按「旧命中 → 新命中」聚合，共 {summary.groups.length} 组）
          </div>
          {summary.groups.map((g, i) => (
            <GroupCard key={i} group={g} />
          ))}
        </>
      )}
    </div>
  )
}

function DiffReportView({ report }: { report: SnapshotDiffResult }) {
  const [filter, setFilter] = useState<DiffCategory | 'all'>('all')
  const cats = report.categories
  const visible = DIFF_CATEGORY_ORDER.filter(
    (c) => (filter === 'all' || filter === c) && cats[c].cells > 0,
  )

  return (
    <div className="snapshot-report">
      <div className="legend" style={{ marginTop: 0, marginBottom: 10 }}>
        基准快照 <strong>{report.base.name}</strong>（{formatTime(report.base.createdAt)}，
        {report.baseStats.active} 条合法启用规则参与重放
        {report.baseStats.invalid > 0 ? `，${report.baseStats.invalid} 条非法已排除` : ''}
        {report.baseStats.disabled > 0 ? `，${report.baseStats.disabled} 条停用已排除` : ''}
        ） → 目标快照 <strong>{report.target.name}</strong>（
        {formatTime(report.target.createdAt)}，{report.targetStats.active} 条合法启用规则参与重放
        {report.targetStats.invalid > 0 ? `，${report.targetStats.invalid} 条非法已排除` : ''}
        {report.targetStats.disabled > 0 ? `，${report.targetStats.disabled} 条停用已排除` : ''}
        ）。在合并后的原子空间上逐单元重放两侧首命中，共对比 {report.comparedCells} 个单元、
        {formatSize(report.comparedSize)} 条报文空间；报告只读，不改动当前规则与快照。
      </div>

      {!report.hasActionDifference && !report.hasReassignment && (
        <div className="notice ok">
          ✓ 两个快照的首命中结果完全一致：参与对比的每个单元，命中规则与动作均未变化。
        </div>
      )}
      {!report.hasActionDifference && report.hasReassignment && (
        <div className="notice ok">
          ✓ 所有报文的首命中动作均未变化；其中 {formatSize(cats.unchanged.groups.reduce((s, g) => s + g.size, 0))}{' '}
          条报文空间的首命中规则易主但动作相同（见「动作未变」类别的同动作易主分组）。
        </div>
      )}
      {report.hasActionDifference && (
        <div className="notice error">
          ✗ 两个快照存在动作级差异：动作改变 {formatSize(cats['action-changed'].size)}，
          由命中变为未命中 {formatSize(cats['became-unmatched'].size)}，
          由未命中变为命中 {formatSize(cats['became-matched'].size)}（单位：条报文空间）。
          明细见下方分类。
        </div>
      )}

      <div className="stats">
        {DIFF_CATEGORY_ORDER.map((c) => (
          <div className={`stat-card ${CATEGORY_META[c].card}`} key={c}>
            <div className="label">{CATEGORY_META[c].label}</div>
            <div className="value" style={{ fontSize: 16 }}>
              {formatSize(cats[c].size)}
            </div>
            <div className="label">{cats[c].cells} 个原子单元</div>
          </div>
        ))}
      </div>

      <div className="filter-bar">
        <button
          className={filter === 'all' ? 'active' : ''}
          onClick={() => setFilter('all')}
        >
          全部类别
        </button>
        {DIFF_CATEGORY_ORDER.map((c) => (
          <button
            key={c}
            className={filter === c ? 'active' : ''}
            onClick={() => setFilter(c)}
          >
            {CATEGORY_META[c].label}（{cats[c].cells}）
          </button>
        ))}
      </div>

      {visible.length === 0 && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          该筛选下没有单元：所选类别在两个快照间为空。
        </div>
      )}
      {visible.map((c) => (
        <CategorySection key={c} summary={cats[c]} />
      ))}
    </div>
  )
}

export function SnapshotPanel({ rules }: Props) {
  const [snapshots, setSnapshots] = useState<RuleSnapshot[]>(() => loadSnapshots())
  const [name, setName] = useState('')
  const [baseId, setBaseId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [report, setReport] = useState<SnapshotDiffResult | null>(null)
  const [reportPair, setReportPair] = useState<{ base: string; target: string } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // 快照列表变更即持久化到 localStorage（不可用时仅保留在内存）
  useEffect(() => {
    persistSnapshots(snapshots)
  }, [snapshots])

  const flash = (text: string) => {
    setNotice(text)
    setTimeout(() => setNotice(null), 4000)
  }

  const save = () => {
    const finalName = name.trim() || `快照 ${snapshots.length + 1}`
    const snap = createSnapshot(finalName, rules)
    setSnapshots((ss) => [...ss, snap])
    setName('')
    flash(`已保存快照「${finalName}」（${rules.length} 条规则）。`)
  }

  const remove = (id: string) => {
    const snap = snapshots.find((s) => s.id === id)
    if (!snap) return
    if (!confirm(`删除快照「${snap.name}」？此操作不可撤销。`)) return
    setSnapshots((ss) => ss.filter((s) => s.id !== id))
    if (baseId === id) setBaseId('')
    if (targetId === id) setTargetId('')
    // 被删快照参与过当前报告：报告失效，一并清除
    if (reportPair && (reportPair.base === id || reportPair.target === id)) {
      setReport(null)
      setReportPair(null)
    }
  }

  const runCompare = () => {
    const base = snapshots.find((s) => s.id === baseId)
    const target = snapshots.find((s) => s.id === targetId)
    if (!base || !target) return
    setReport(compareSnapshots(base, target))
    setReportPair({ base: base.id, target: target.id })
  }

  const sameSelection = baseId !== '' && baseId === targetId

  return (
    <div className="panel snapshot-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>审计快照对比（只读）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          为当前规则集保存命名快照，任选两个快照在合并原子空间上逐单元重放首命中并对比；
          对比不改动当前规则与快照
        </span>
      </div>

      <div className="snapshot-save-row">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder={`快照名称（留空默认为「快照 ${snapshots.length + 1}」）`}
          spellCheck={false}
          onKeyDown={(e) => {
            if (e.key === 'Enter') save()
          }}
        />
        <button className="primary" onClick={save} disabled={rules.length === 0}>
          保存当前规则为快照
        </button>
      </div>
      {rules.length === 0 && (
        <div className="legend" style={{ marginTop: -6, marginBottom: 8 }}>
          当前没有规则，无法保存快照。
        </div>
      )}

      {notice && <div className="notice info">{notice}</div>}

      {snapshots.length === 0 ? (
        <div className="notice info" style={{ marginBottom: 0 }}>
          还没有快照。输入名称并点击「保存当前规则为快照」，即可冻结当前规则集；
          之后的规则编辑、调序、启停都不会影响已保存的快照。保存两个快照后即可生成对比报告。
        </div>
      ) : (
        <>
          <div style={{ overflowX: 'auto' }}>
            <table className="rule-table snapshot-table">
              <thead>
                <tr>
                  <th>基准</th>
                  <th>目标</th>
                  <th>快照名称</th>
                  <th>保存时间</th>
                  <th>规则构成</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s) => {
                  const stats = snapshotRuleStats(s)
                  return (
                    <tr key={s.id}>
                      <td className="enable-cell">
                        <input
                          type="radio"
                          name="snapshot-base"
                          checked={baseId === s.id}
                          onChange={() => setBaseId(s.id)}
                          title="选为对比基准（旧）"
                        />
                      </td>
                      <td className="enable-cell">
                        <input
                          type="radio"
                          name="snapshot-target"
                          checked={targetId === s.id}
                          onChange={() => setTargetId(s.id)}
                          title="选为对比目标（新）"
                        />
                      </td>
                      <td className="reorder-rule-name">{s.name}</td>
                      <td className="idx-cell">{formatTime(s.createdAt)}</td>
                      <td className="muted-text">
                        共 {stats.total} 条 · 参与对比 {stats.active} 条
                        {stats.invalid > 0 ? ` · 非法 ${stats.invalid}` : ''}
                        {stats.disabled > 0 ? ` · 停用 ${stats.disabled}` : ''}
                      </td>
                      <td>
                        <button
                          className="danger ghost"
                          style={{ padding: '4px 8px', fontSize: 12 }}
                          onClick={() => remove(s.id)}
                        >
                          删除
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="snapshot-compare-row">
            <button
              className="primary"
              disabled={!baseId || !targetId}
              title={!baseId || !targetId ? '先在列表中选择基准与目标快照' : '生成对比报告'}
              onClick={runCompare}
            >
              生成对比报告
            </button>
            <button
              className="ghost"
              disabled={!baseId && !targetId}
              onClick={() => {
                setBaseId(targetId)
                setTargetId(baseId)
              }}
            >
              交换基准 / 目标
            </button>
            {sameSelection && (
              <span className="muted-text">
                基准与目标为同一快照，报告将显示完全一致。
              </span>
            )}
            {snapshots.length < 2 && (
              <span className="muted-text">再保存一个快照后即可对比。</span>
            )}
          </div>
        </>
      )}

      {report && <DiffReportView report={report} />}
    </div>
  )
}
