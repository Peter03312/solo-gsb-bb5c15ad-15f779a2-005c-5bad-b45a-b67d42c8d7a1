import { useMemo, useState } from 'react'
import { previewReorder } from './audit/reorder'
import type {
  ReorderPacket,
  ReorderRuleView,
  TrafficChange,
} from './audit/reorder'
import type { RuleInput, StatusLevel } from './audit/types'
import { formatPacket, formatSize } from './format'

const STATUS_TEXT: Record<StatusLevel, string> = {
  reachable: '可达',
  'partial-shadowed': '部分遮蔽',
  'fully-shadowed': '完全遮蔽',
  invalid: '非法',
  disabled: '停用',
  empty: '空区域',
}

const STATUS_CLS: Record<StatusLevel, string> = {
  reachable: 'reachable',
  'partial-shadowed': 'partial-shadowed',
  'fully-shadowed': 'fully-shadowed',
  invalid: 'invalid',
  disabled: 'muted',
  empty: 'muted',
}

interface Props {
  current: RuleInput[]
  candidate: RuleInput[]
  onConfirm: () => void
  onCancel: () => void
}

function CopyPacket({ packet }: { packet: ReorderPacket }) {
  const [copied, setCopied] = useState(false)
  const text = formatPacket(packet)
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
      {copied ? '已复制' : '复制报文'}
    </button>
  )
}

function StatusTransition({ oldStatus, newStatus }: { oldStatus: StatusLevel; newStatus: StatusLevel }) {
  const changed = oldStatus !== newStatus
  return (
    <span className={changed ? 'reorder-status-changed' : ''}>
      <span className={`badge ${STATUS_CLS[oldStatus]}`}>{STATUS_TEXT[oldStatus]}</span>
      <span className="muted-text reorder-arrow">→</span>
      <span className={`badge ${STATUS_CLS[newStatus]}`}>{STATUS_TEXT[newStatus]}</span>
    </span>
  )
}

function SizeDelta({ view }: { view: ReorderRuleView }) {
  if (view.oldStatus === 'invalid' && view.newStatus === 'invalid') {
    return <span className="muted-text">—（非法不参与分析）</span>
  }
  const d = view.sizeDelta
  const cls = d > 0 ? 'delta-up' : d < 0 ? 'delta-down' : 'muted-text'
  const sign = d > 0 ? '+' : d < 0 ? '−' : '±'
  return (
    <span>
      <span className="muted-text">{formatSize(view.oldEffectiveSize)}</span>
      <span className="muted-text reorder-arrow">→</span>
      <strong>{formatSize(view.newEffectiveSize)}</strong>
      <span className={`reorder-delta ${cls}`}>
        {' '}
        （{sign}
        {formatSize(Math.abs(d))}）
      </span>
    </span>
  )
}

function RuleChangeTable({ rules }: { rules: ReorderRuleView[] }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table className="rule-table reorder-table">
        <thead>
          <tr>
            <th>规则</th>
            <th>旧序号</th>
            <th>新序号</th>
            <th>状态（旧 → 新）</th>
            <th>有效报文空间（旧 → 新，变化量）</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((v) => (
            <tr key={v.id} className={v.auditChanged ? 'reorder-row-changed' : 'reorder-row-moved-only'}>
              <td>
                <span className="reorder-rule-name">{v.name}</span>
                {!v.auditChanged && (
                  <span className="collective-tag" title="仅列表位置变化，审计结果不变">
                    仅序号变化
                  </span>
                )}
              </td>
              <td className="idx-cell">#{v.oldIndex + 1}</td>
              <td className="idx-cell">
                #{v.newIndex + 1}
                {v.moved && <span className="muted-text"> （移动 {Math.abs(v.newIndex - v.oldIndex)} 位）</span>}
              </td>
              <td>
                <StatusTransition oldStatus={v.oldStatus} newStatus={v.newStatus} />
              </td>
              <td className="reorder-size-cell">
                <SizeDelta view={v} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ActionPill({ action }: { action: string }) {
  return <span className="action-pill">{action}</span>
}

function TrafficCard({ change }: { change: TrafficChange }) {
  return (
    <div className={`traffic-card ${change.actionChanged ? 'traffic-action-changed' : ''}`}>
      <div className="traffic-packet">
        <span className="mono">{formatPacket(change.packet)}</span>
        <CopyPacket packet={change.packet} />
      </div>
      <div className="traffic-flow">
        <span className="traffic-side">
          <span className="idx-cell">#{change.oldIndex + 1}</span>
          <span className="reorder-rule-name">{change.oldName}</span>
          <ActionPill action={change.oldAction} />
        </span>
        <span className="muted-text reorder-arrow">→</span>
        <span className="traffic-side">
          <span className="idx-cell">#{change.newIndex + 1}</span>
          <span className="reorder-rule-name">{change.newName}</span>
          <ActionPill action={change.newAction} />
        </span>
        {change.actionChanged ? (
          <span className="traffic-alert">首命中动作变化</span>
        ) : (
          <span className="traffic-same muted-text">动作相同</span>
        )}
      </div>
      <div className="muted-text traffic-size">
        影响报文空间 {formatSize(change.size)}（{change.cells} 个原子单元）
      </div>
    </div>
  )
}

export function ReorderPreviewModal({ current, candidate, onConfirm, onCancel }: Props) {
  const preview = useMemo(() => previewReorder(current, candidate), [current, candidate])

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">调序影响预览（确认前规则顺序不会改变）</div>
        <div className="modal-body">
          {preview.hasDifference ? (
            <div className="notice info" style={{ marginTop: 0 }}>
              共 <strong>{preview.affectedRuleCount}</strong> 条规则受影响；
              <strong> {preview.actionChanges.length}</strong> 组流量的首命中动作发生变化，
              另有 <strong>{preview.sameActionChanges.length}</strong> 组流量仅更换命中规则（动作不变）；
              归属转移的报文空间共 <strong>{formatSize(preview.totalReassignedSize)}</strong>。
              下表与样例均按规则 id 对齐当前顺序与候选顺序的审计结果。
            </div>
          ) : (
            <div className="notice" style={{ marginTop: 0, background: 'var(--ok-bg)', border: '1px solid rgba(54,192,138,.35)', color: '#b8f0d8' }}>
              无实际差异：候选顺序下所有规则的状态、有效报文空间与每个报文的首命中结果均保持不变
              {preview.rules.length > 0 ? '（下列规则仅列表序号变化）' : ''}。可以直接取消，或仍应用该顺序。
            </div>
          )}

          <h3 className="reorder-section-title">
            受影响规则（{preview.rules.length}）
          </h3>
          {preview.rules.length === 0 ? (
            <div className="notice info" style={{ marginTop: 0 }}>没有受影响的规则。</div>
          ) : (
            <RuleChangeTable rules={preview.rules} />
          )}

          {preview.actionChanges.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                首命中动作发生变化的流量（{preview.actionChanges.length}，每组附可复现样例报文）
              </h3>
              <div>
                {preview.actionChanges.map((c, i) => (
                  <TrafficCard key={`a-${i}`} change={c} />
                ))}
              </div>
            </>
          )}

          {preview.sameActionChanges.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                仅更换命中规则、动作不变的流量（{preview.sameActionChanges.length}）
              </h3>
              <div>
                {preview.sameActionChanges.map((c, i) => (
                  <TrafficCard key={`s-${i}`} change={c} />
                ))}
              </div>
            </>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onCancel}>取消（保持原顺序）</button>
          <button className="primary" onClick={onConfirm}>
            {preview.hasDifference ? '确认应用候选顺序' : '仍要应用该顺序'}
          </button>
        </div>
      </div>
    </div>
  )
}
