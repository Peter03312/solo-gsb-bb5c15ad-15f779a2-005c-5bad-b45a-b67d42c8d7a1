import { useMemo, useRef, useState, type ReactNode } from 'react'
import { analyzeSimplify } from './audit/simplify'
import type {
  SimplifyCandidate,
  SimplifyPacket,
  SimplifyResult,
  TakeoverConflict,
  TakeoverGroup,
} from './audit/simplify'
import type { RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
  onDeleteRule: (ruleId: string) => void
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
function RegionView({
  regions,
}: {
  regions: SimplifyCandidate['takeovers'][number]['regions']
}) {
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

function PacketBox({
  packet,
  note,
}: {
  packet: SimplifyPacket
  note: ReactNode
}) {
  return (
    <div className="packet-box">
      <span className="tag reachable">代表报文</span>
      <span className="mono">{formatPacket(packet)}</span>
      <span className="arrow-note">{note}</span>
      <CopyButton text={formatPacket(packet)} />
    </div>
  )
}

function TakeoverView({ group, totalSize }: { group: TakeoverGroup; totalSize: number }) {
  return (
    <div className="takeover-block">
      <div className="takeover-head">
        <span className="idx-cell">#{group.ruleIndex + 1}</span>
        <span className="reorder-rule-name">{group.ruleName}</span>
        <span className="action-pill">{group.action}</span>
        <span className="spacer" />
        <span className="muted-text">
          接管 {formatSize(group.size)} 条报文空间（{group.cells} 个原子单元，占该规则有效流量{' '}
          {formatPercent(totalSize === 0 ? 0 : group.size / totalSize)}）
        </span>
      </div>
      <PacketBox
        packet={group.packet}
        note={
          <>
            → 删除后命中 #{group.ruleIndex + 1} {group.ruleName}，动作仍为
            <span className="action-pill">{group.action}</span>
          </>
        }
      />
      <RegionView regions={group.regions} />
    </div>
  )
}

function ConflictView({ conflict }: { conflict: TakeoverConflict }) {
  return (
    <div className="takeover-block conflict-block">
      <div className="takeover-head">
        {conflict.kind === 'unmatched' ? (
          <>
            <span className="action-pill conflict-pill">未命中任何规则</span>
            <span className="traffic-alert">删除后该流量无人接管</span>
          </>
        ) : (
          <>
            <span className="idx-cell">#{conflict.ruleIndex! + 1}</span>
            <span className="reorder-rule-name">{conflict.ruleName}</span>
            <span className="action-pill conflict-pill">{conflict.afterAction}</span>
            <span className="traffic-alert">首命中动作改变</span>
          </>
        )}
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(conflict.size)} 条报文空间（{conflict.cells} 个原子单元）
        </span>
      </div>
      <PacketBox
        packet={conflict.packet}
        note={
          conflict.kind === 'unmatched' ? (
            <>→ 删除后不命中任何规则（默认动作未知），不能安全删除</>
          ) : (
            <>
              → 删除后命中 #{conflict.ruleIndex! + 1} {conflict.ruleName}，动作变为
              <span className="action-pill conflict-pill">{conflict.afterAction}</span>
            </>
          )
        }
      />
      <RegionView regions={conflict.regions} />
    </div>
  )
}

function CandidateCard({
  item,
  stale,
  onRequestDelete,
}: {
  item: SimplifyCandidate
  stale: boolean
  onRequestDelete: (item: SimplifyCandidate) => void
}) {
  const [open, setOpen] = useState(item.safe)
  return (
    <div className={`entry ${item.safe ? 'entry-safe-delete' : 'entry-unsafe-delete'} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{item.ruleIndex + 1}</span>
        <span className="title">{item.ruleName}</span>
        {item.safe ? (
          <span className="badge safe-badge">可安全删除</span>
        ) : (
          <span className="badge unsafe-badge">删除会改变动作</span>
        )}
        <span className="spacer" />
        <span className="meta">
          有效流量 {formatSize(item.effectiveSize)}（{item.effectiveCells} 单元） · 动作{' '}
          <span className="action-pill">{item.action}</span>
        </span>
      </div>
      {open && (
        <div className="entry-body" onClick={(e) => e.stopPropagation()}>
          <div className="code-list" style={{ marginBottom: 10 }}>
            <div className="line">
              规则声明：{item.cidrText} · 端口 {formatPortRange(item.portStart, item.portEnd)} ·{' '}
              {item.protocol} · {item.action}
            </div>
          </div>

          {item.safe ? (
            <>
              <h3 className="reorder-section-title" style={{ marginTop: 0 }}>
                删除后由以下后续规则以相同动作接管（区域精确互斥，合计 = 全部有效流量）
              </h3>
              {item.takeovers.map((g) => (
                <TakeoverView key={g.ruleId} group={g} totalSize={item.effectiveSize} />
              ))}
              <div className="safe-action-row">
                <button
                  className="primary danger"
                  disabled={stale}
                  onClick={() => onRequestDelete(item)}
                  title={stale ? '分析已过期，请先重新分析' : '预览并确认删除该规则'}
                >
                  删除该规则（动作无损）
                </button>
                {stale && (
                  <span className="muted-text">旧分析已过期，按钮已禁用，请重新分析</span>
                )}
              </div>
            </>
          ) : (
            <>
              <h3 className="reorder-section-title" style={{ marginTop: 0 }}>
                以下有效流量在删除后最终动作会改变（含变为未命中），因此不可安全删除
              </h3>
              {item.conflicts.map((c, i) => (
                <ConflictView key={`${c.kind}-${i}`} conflict={c} />
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function DeleteConfirmModal({
  item,
  stale,
  onConfirm,
  onCancel,
}: {
  item: SimplifyCandidate
  stale: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">确认删除规则（无损精简建议）</div>
        <div className="modal-body">
          <div className="notice info" style={{ marginTop: 0 }}>
            以下规则的全部有效流量在删除后都会被后续规则以<strong>相同动作</strong>接管，
            任何报文的最终动作都不变。删除后请按需重新分析（其余建议需重新计算）。
          </div>
          <div className="code-list">
            <div className="line">
              <strong>#{item.ruleIndex + 1} {item.ruleName}</strong>
            </div>
            <div className="line">
              {item.cidrText} · 端口 {formatPortRange(item.portStart, item.portEnd)} ·{' '}
              {item.protocol} · 动作 <span className="action-pill">{item.action}</span>
            </div>
            <div className="line">
              有效流量 {formatSize(item.effectiveSize)}，由 {item.takeovers.length}{' '}
              条后续规则以相同动作接管：
            </div>
          </div>
          <div style={{ overflowX: 'auto', marginTop: 8 }}>
            <table className="rule-table reorder-table">
              <thead>
                <tr>
                  <th>接管规则</th>
                  <th>动作</th>
                  <th>接管报文空间</th>
                  <th>代表报文</th>
                </tr>
              </thead>
              <tbody>
                {item.takeovers.map((g) => (
                  <tr key={g.ruleId}>
                    <td>
                      <span className="idx-cell">#{g.ruleIndex + 1}</span>{' '}
                      {g.ruleName}
                    </td>
                    <td><span className="action-pill">{g.action}</span></td>
                    <td className="goal-num">{formatSize(g.size)}</td>
                    <td className="mono">{formatPacket(g.packet)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onCancel}>取消</button>
          <button className="primary danger" disabled={stale} onClick={onConfirm}>
            {stale ? '分析已过期，请重新分析' : `确认删除 #${item.ruleIndex + 1} ${item.ruleName}`}
          </button>
        </div>
      </div>
    </div>
  )
}

export function SimplifyPanel({ rules, onDeleteRule }: Props) {
  const [result, setResult] = useState<SimplifyResult | null>(null)
  const [pendingDelete, setPendingDelete] = useState<SimplifyCandidate | null>(null)
  // 分析时刻的规则快照引用：规则编辑 / 调序 / 删除都会产生新数组，据此判定过期
  const snapshotRef = useRef<RuleInput[] | null>(null)
  const stale = result !== null && snapshotRef.current !== rules

  const candidates = useMemo(
    () => (result ? result.items.filter((i): i is SimplifyCandidate => i.kind === 'candidate') : []),
    [result],
  )
  const safe = candidates.filter((c) => c.safe)
  const unsafe = candidates.filter((c) => !c.safe)

  const runAnalysis = () => {
    setResult(analyzeSimplify(rules))
    snapshotRef.current = rules
  }

  const confirmDelete = () => {
    if (!pendingDelete) return
    onDeleteRule(pendingDelete.ruleId)
    setPendingDelete(null)
  }

  return (
    <div className="panel simplify-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>无损精简（模拟删除，动作不变才建议）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          仅对已启用、合法且当前有有效流量的规则逐条模拟单独删除；在同一套 IPv4 / 端口 /
          协议原子空间中逐单元比较删除前后的最终动作，未命中视为独立结果
        </span>
        <div style={{ flex: 1 }} />
        <button className="primary" onClick={runAnalysis}>
          {result ? '重新分析' : '分析'}
        </button>
      </div>

      {!result && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          点击「分析」：对每条有有效流量的规则模拟删除，检查其原有效流量是否全部由
          <strong>后续规则以相同动作</strong>接管（变为未命中也算动作改变）。分析是只读的，
          删除需在建议卡片中二次确认。
        </div>
      )}

      {result && (
        <>
          {stale && (
            <div className="notice error">
              ⚠ 规则自上次分析后已被编辑、调序或删除，以下分析结果<strong>已过期</strong>：
              删除按钮已禁用。请点击「重新分析」后再应用建议。
            </div>
          )}
          <div className="legend simplify-summary">
            分析 {result.analyzedCount} 条（启用、合法、有有效流量）：
            <span className="safe-text"> {result.safeCount} 条可安全删除</span>，
            <span className="unsafe-text"> {result.unsafeCount} 条删除会改变动作</span>
            {result.skippedNoTraffic > 0 && `；${result.skippedNoTraffic} 条无有效流量未模拟`}
            {result.skippedDisabled > 0 && `；${result.skippedDisabled} 条停用未模拟`}
            {result.skippedInvalid > 0 && `；${result.skippedInvalid} 条非法未模拟`}
          </div>

          {safe.length === 0 && unsafe.length === 0 && (
            <div className="notice info" style={{ marginBottom: 0 }}>
              没有可模拟的规则（启用且合法的规则均无有效流量）。
            </div>
          )}

          {safe.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                可安全删除（{safe.length}）—— 有效流量全部由后续规则以相同动作接管
              </h3>
              {safe.map((item) => (
                <CandidateCard
                  key={item.ruleId}
                  item={item}
                  stale={stale}
                  onRequestDelete={setPendingDelete}
                />
              ))}
            </>
          )}

          {unsafe.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                不可安全删除（{unsafe.length}）—— 删除后部分报文动作改变或变为未命中
              </h3>
              {unsafe.map((item) => (
                <CandidateCard
                  key={item.ruleId}
                  item={item}
                  stale={stale}
                  onRequestDelete={setPendingDelete}
                />
              ))}
            </>
          )}
        </>
      )}

      {pendingDelete && (
        <DeleteConfirmModal
          item={pendingDelete}
          stale={stale}
          onConfirm={confirmDelete}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </div>
  )
}
