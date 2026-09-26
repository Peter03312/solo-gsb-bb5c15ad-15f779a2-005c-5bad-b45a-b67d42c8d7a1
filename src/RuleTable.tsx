import { useState } from 'react'
import type { RuleInput } from './audit/types'
import type { AuditResultEntry } from './audit/types'

interface Props {
  rules: RuleInput[]
  entries: AuditResultEntry[]
  onChange: (index: number, patch: Partial<RuleInput>) => void
  onRemove: (index: number) => void
  onDuplicate: (index: number) => void
  onReorder: (from: number, to: number) => void
  onAdd: () => void
}

const PROTOCOLS = ['ANY', 'TCP', 'UDP']

const STATUS_BADGE: Record<string, { text: string; cls: string }> = {
  reachable: { text: '可达', cls: 'reachable' },
  'partial-shadowed': { text: '部分遮蔽', cls: 'partial-shadowed' },
  'fully-shadowed': { text: '完全遮蔽', cls: 'fully-shadowed' },
  invalid: { text: '非法', cls: 'invalid' },
  disabled: { text: '停用', cls: 'muted' },
  empty: { text: '空', cls: 'muted' },
}

export function RuleTable({
  rules,
  entries,
  onChange,
  onRemove,
  onDuplicate,
  onReorder,
  onAdd,
}: Props) {
  const [dragIndex, setDragIndex] = useState<number | null>(null)
  const [overIndex, setOverIndex] = useState<number | null>(null)

  const handleDrop = (target: number) => {
    if (dragIndex !== null && dragIndex !== target) {
      onReorder(dragIndex, target)
    }
    setDragIndex(null)
    setOverIndex(null)
  }

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 10 }}>
        <h2 style={{ margin: 0 }}>规则列表（自上而下，首条命中）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          拖拽 ⠿ 手柄或整行可排序；松手后先弹出「调序影响预览」，确认后才会应用新顺序
        </span>
        <div style={{ flex: 1 }} />
        <button className="primary" onClick={onAdd}>
          ＋ 新增规则
        </button>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="rule-table">
          <thead>
            <tr>
              <th style={{ width: 34 }}></th>
              <th style={{ width: 44 }}>#</th>
              <th style={{ width: 52 }} title="停用后该规则不参与首命中分析，效果等同于暂时移除">启用</th>
              <th style={{ minWidth: 150 }}>名称</th>
              <th style={{ minWidth: 150 }}>源 IPv4 CIDR</th>
              <th style={{ minWidth: 170 }}>源端口区间</th>
              <th style={{ width: 90 }}>协议</th>
              <th style={{ minWidth: 90 }}>动作</th>
              <th style={{ width: 92 }}>状态</th>
              <th style={{ width: 110 }}>操作</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, i) => {
              const entry = entries[i]
              const statusKey = entry ? entry.kind : 'empty'
              const badge =
                entry?.kind === 'invalid'
                  ? STATUS_BADGE.invalid
                  : entry?.kind === 'valid'
                    ? STATUS_BADGE[entry.status]
                    : STATUS_BADGE.empty
              return (
                <tr
                  key={rule.id}
                  className={[
                    'rule-row',
                    dragIndex === i ? 'dragging' : '',
                    overIndex === i && dragIndex !== i ? 'drag-over' : '',
                    statusKey === 'invalid' ? 'row-invalid' : '',
                    rule.enabled ? '' : 'row-disabled',
                  ].join(' ')}
                  draggable
                  onDragStart={(e) => {
                    setDragIndex(i)
                    e.dataTransfer.effectAllowed = 'move'
                    e.dataTransfer.setData('text/plain', String(i))
                  }}
                  onDragOver={(e) => {
                    e.preventDefault()
                    e.dataTransfer.dropEffect = 'move'
                    if (overIndex !== i) setOverIndex(i)
                  }}
                  onDragLeave={() => {
                    if (overIndex === i) setOverIndex(null)
                  }}
                  onDrop={(e) => {
                    e.preventDefault()
                    handleDrop(i)
                  }}
                  onDragEnd={() => {
                    setDragIndex(null)
                    setOverIndex(null)
                  }}
                >
                  <td>
                    <span className="drag-handle" title="拖拽排序">
                      ⠿
                    </span>
                  </td>
                  <td className="idx-cell">{i + 1}</td>
                  <td className="enable-cell">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={(e) => onChange(i, { enabled: e.target.checked })}
                      title={rule.enabled ? '点击停用（不参与分析）' : '点击启用'}
                    />
                  </td>
                  <td>
                    <input
                      value={rule.name}
                      onChange={(e) => onChange(i, { name: e.target.value })}
                      placeholder={`规则 #${i + 1}`}
                    />
                  </td>
                  <td>
                    <input
                      className={entry?.kind === 'invalid' ? 'invalid-field' : ''}
                      value={rule.cidr}
                      onChange={(e) => onChange(i, { cidr: e.target.value })}
                      placeholder="10.0.0.0/8"
                      spellCheck={false}
                    />
                  </td>
                  <td>
                    <div className="port-cell">
                      <input
                        className={entry?.kind === 'invalid' ? 'invalid-field' : ''}
                        value={rule.portStart}
                        onChange={(e) => onChange(i, { portStart: e.target.value })}
                        placeholder="0"
                      />
                      <span className="muted-text">–</span>
                      <input
                        className={entry?.kind === 'invalid' ? 'invalid-field' : ''}
                        value={rule.portEnd}
                        onChange={(e) => onChange(i, { portEnd: e.target.value })}
                        placeholder="65535"
                      />
                    </div>
                  </td>
                  <td>
                    <select
                      value={rule.protocol.toUpperCase()}
                      onChange={(e) => onChange(i, { protocol: e.target.value })}
                    >
                      {PROTOCOLS.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      value={rule.action}
                      onChange={(e) => onChange(i, { action: e.target.value })}
                      placeholder="allow / deny"
                    />
                  </td>
                  <td>
                    {badge && <span className={`badge ${badge.cls}`}>{badge.text}</span>}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button title="复制" onClick={() => onDuplicate(i)}>
                        复制
                      </button>
                      <button className="danger" title="删除" onClick={() => onRemove(i)}>
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
