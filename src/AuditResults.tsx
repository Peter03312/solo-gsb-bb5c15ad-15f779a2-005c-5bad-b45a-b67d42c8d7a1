import { useState } from 'react'
import type {
  AuditEntry,
  AuditInvalidEntry,
  AuditReport,
  ExamplePacket,
  MinExplanation,
} from './audit/types'
import type {
  ExceptionPacket,
  ExemptionReport,
  RuleExemption,
} from './audit/exemption'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

type Filter =
  | 'all'
  | 'issues'
  | 'fully'
  | 'partial'
  | 'invalid'
  | 'disabled'
  | 'reachable'
  | 'exempt-full'
  | 'exempt-partial'
  | 'exempt-none'

const STATUS_TEXT: Record<AuditEntry['status'], string> = {
  reachable: '可达',
  'partial-shadowed': '部分遮蔽',
  'fully-shadowed': '完全遮蔽',
  disabled: '停用',
  empty: '空区域',
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

function PacketLine({ packet }: { packet: ExamplePacket }) {
  return (
    <div className="packet-box">
      <span className={`tag ${packet.kind}`}>
        {packet.kind === 'reachable' ? '可达样例' : '遮蔽样例'}
      </span>
      <span>{formatPacket(packet)}</span>
      <span className="arrow-note">
        → 命中 #{packet.matchedRuleIndex + 1} {packet.matchedRuleName}（{packet.action}）
      </span>
      <CopyButton text={formatPacket(packet)} />
    </div>
  )
}

function ExemptPacketLine({
  packet,
  kind,
  note,
}: {
  packet: ExceptionPacket
  kind: 'exempt' | 'pending'
  note: string
}) {
  return (
    <div className="packet-box">
      <span className={`tag ${kind === 'exempt' ? 'reachable' : 'shadowed'}`}>
        {kind === 'exempt' ? '已豁免代表报文' : '待处理代表报文'}
      </span>
      <span>{formatPacket(packet)}</span>
      <span className="arrow-note">{note}</span>
      <CopyButton text={formatPacket(packet)} />
    </div>
  )
}

/**
 * 审计例外豁免块：遮蔽区域在有效例外下的精确分解。
 * 仅展示豁免标记，不改变上方审计结论（状态、有效 / 声明空间均保持原值）。
 */
function ExemptionBlock({ exemption }: { exemption: RuleExemption }) {
  const renderRegions = (regions: RuleExemption['exemptRegions']) => (
    <div className="code-list">
      {regions.map((g) => (
        <div key={g.protocol} className="line">
          <strong>{g.protocol}</strong> · {formatSize(g.size)} 条报文空间
          {g.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} × {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )

  return (
    <div className="detail-block exemption-block">
      <h3>审计例外豁免（不改变上述审计结论）</h3>
      <div className="exemption-summary">
        <span className="badge exempt-badge">已豁免 {formatSize(exemption.exemptSize)}</span>
        <span className="badge exempt-pending-badge">待处理 {formatSize(exemption.pendingSize)}</span>
        <span className="muted-text">
          遮蔽区域共 {formatSize(exemption.blockedSize)}；豁免占比{' '}
          {formatPercent(exemption.exemptRatio)}
        </span>
      </div>

      {exemption.coverages.filter((c) => !c.noOverlap).length > 0 && (
        <>
          <div className="goal-block-title">已豁免区域（有效例外覆盖的并集，重叠处去重）</div>
          {exemption.exemptRepresentative && (
            <ExemptPacketLine
              packet={exemption.exemptRepresentative}
              kind="exempt"
              note="该报文被有效例外覆盖，标记为已豁免"
            />
          )}
          {renderRegions(exemption.exemptRegions)}
        </>
      )}

      {exemption.pendingSize > 0 ? (
        <>
          <div className="goal-block-title">待处理区域（遮蔽区域减去豁免并集，仍需整改）</div>
          {exemption.pendingRepresentative && (
            <ExemptPacketLine
              packet={exemption.pendingRepresentative}
              kind="pending"
              note="该报文未被任何有效例外覆盖，仍计入审计问题"
            />
          )}
          {renderRegions(exemption.pendingRegions)}
        </>
      ) : (
        <div className="notice ok" style={{ marginTop: 8 }}>
          ✓ 该规则的全部遮蔽区域均被未过期的有效例外覆盖，标记为「已全部豁免」。
        </div>
      )}

      <div className="goal-block-title">适用例外（{exemption.coverages.length} 条）</div>
      <div className="code-list">
        {exemption.coverages.map((c) => (
          <div key={c.exceptionId} className="line">
            {c.noOverlap ? (
              <span className="muted-text">
                例外 {c.cidrText} · 端口 {formatPortRange(c.portStart, c.portEnd)} · {c.protocol}
                ：与当前遮蔽区域<strong>无交集</strong>，本次不豁免任何报文
              </span>
            ) : (
              <>
                {c.cidrText} · 端口 {formatPortRange(c.portStart, c.portEnd)} · {c.protocol}
                ：豁免 {formatSize(c.coveredSize)}（{c.coveredCells} 单元）
              </>
            )}
            <div className="muted-text" style={{ paddingLeft: 12 }}>
              到期：{c.expiresAtMs === null ? '永久' : c.expiresAtText} · 说明：{c.notes}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * 最小解释集：前序合法启用规则中，联合覆盖本完全遮蔽规则全部声明单元的
 * 最少规则集合（精确求解；同基数按规则序号数组字典序取唯一结果）。
 */
function MinExplanationBlock({ min }: { min: MinExplanation }) {
  return (
    <div className="detail-block" style={{ marginTop: 14 }}>
      <h3>
        最小解释集（前序合法启用规则中联合覆盖全部 {min.declaredCells} 个声明单元的最少集合）
      </h3>
      {min.skipped ? (
        <div className="notice warn">
          候选来源共 {min.candidateCount} 条，超过精确求解上限 {min.exactLimit} 条：
          <strong>不计算最小解释集</strong>，不以贪心近似结果冒充最优。
          可在减少规则或缩小规则范围后重新审计。
        </div>
      ) : (
        <div>
          <div className="muted-text" style={{ marginBottom: 6 }}>
            候选来源 {min.candidateCount} 条（≤ {min.exactLimit}，已精确穷举求解）；
            入选 <strong>{min.members.length}</strong> 条，联合覆盖{' '}
            <strong>{min.coveredCells}</strong> / {min.declaredCells} 个声明单元
            {min.members.length === 1 && '——单条前序规则已能独立全覆盖'}。
          </div>
          {min.members.map((m) => (
            <div className="source-row" key={m.ruleIndex}>
              <span className="src-idx">#{m.ruleIndex + 1}</span>
              <span>{m.ruleName}</span>
              <span className="muted-text">（{m.action}）</span>
              <span className="spacer" />
              <span className="muted-text">
                不可替代 {m.uniqueCells} 单元 / 共盖 {m.coveredCells} 单元
              </span>
            </div>
          ))}
          <div className="muted-text" style={{ margin: '8px 0 2px' }}>
            各入选规则相对解释集不可替代的代表报文（实际首命中规则在报文后标注）：
          </div>
          {min.members.map((m) => (
            <div className="packet-box" key={`pkt-${m.ruleIndex}`}>
              <span className="tag shadowed" title={`不可替代单元 ${m.uniqueCells} 个`}>
                #{m.ruleIndex + 1} 不可替代
              </span>
              <span>{formatPacket(m.representative)}</span>
              <span className="arrow-note">
                → 命中 #{m.representative.matchedRuleIndex + 1}{' '}
                {m.representative.matchedRuleName}（{m.representative.action}）
              </span>
              <CopyButton text={formatPacket(m.representative)} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ValidEntry({
  entry,
  exemption,
}: {
  entry: AuditEntry
  exemption?: RuleExemption
}) {
  const [open, setOpen] = useState(
    entry.status === 'fully-shadowed' || entry.status === 'disabled',
  )
  const cls =
    entry.status === 'fully-shadowed'
      ? 'entry-fully-shadowed'
      : entry.status === 'partial-shadowed'
        ? 'entry-partial-shadowed'
        : entry.status === 'disabled'
          ? 'entry-disabled'
          : 'entry-reachable'

  if (entry.status === 'disabled') {
    return (
      <div className={`entry ${cls} ${open ? 'open' : ''}`}>
        <div className="entry-header" onClick={() => setOpen((v) => !v)}>
          <span className="chevron">▶</span>
          <span className="idx-cell">#{entry.index + 1}</span>
          <span className="title">{entry.name}</span>
          <span className="badge muted">停用 · 不参与分析</span>
          <span className="spacer" />
          <span className="meta muted-text">
            声明 {formatSize(entry.declaredSize)}（启用后才计入首命中分析）
          </span>
        </div>
        {open && (
          <div className="entry-body">
            <div className="code-list">
              <div className="line">CIDR：{entry.cidrText}</div>
              <div className="line">
                源端口：{formatPortRange(entry.portStart, entry.portEnd)}
              </div>
              <div className="line">协议：{entry.protocol}</div>
              <div className="line">动作：{entry.action}</div>
            </div>
            <div className="muted-text" style={{ marginTop: 8 }}>
              该规则当前已停用：不参与首命中计算，对其他规则的遮蔽 / 可达性没有影响；
              在「无损精简」中也不会被模拟删除。重新勾选列表中的「启用」即可恢复分析。
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className={`entry ${cls} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{entry.index + 1}</span>
        <span className="title">{entry.name}</span>
        <span className={`badge ${entry.status}`}>{STATUS_TEXT[entry.status]}</span>
        {entry.collectiveCover && (
          <span className="collective-tag" title="没有任何单条前序规则可独立遮蔽它，由多条规则的并集共同覆盖">
            共同覆盖
          </span>
        )}
        {exemption && (
          exemption.fullyExempt ? (
            <span className="badge exempt-badge" title="遮蔽区域已全部被未过期的有效例外覆盖">
              已全部豁免
            </span>
          ) : exemption.exemptSize > 0 ? (
            <span className="badge exempt-partial-badge" title="部分遮蔽区域被有效例外覆盖，剩余仍待处理">
              部分豁免 {formatPercent(exemption.exemptRatio)}
            </span>
          ) : undefined
        )}
        <span className="spacer" />
        <span className="meta">
          有效 {formatSize(entry.effectiveSize)} / 声明 {formatSize(entry.declaredSize)}（
          {formatPercent(entry.effectiveRatio)}）
        </span>
      </div>

      {open && (
        <div className="entry-body">
          <div className="detail-grid">
            <div className="detail-block">
              <h3>规则声明</h3>
              <div className="code-list">
                <div className="line">CIDR：{entry.cidrText}</div>
                <div className="line">
                  源端口：{formatPortRange(entry.portStart, entry.portEnd)}
                </div>
                <div className="line">协议：{entry.protocol}</div>
                <div className="line">动作：{entry.action}</div>
              </div>
            </div>

            <div className="detail-block">
              <h3>实际可达区域（首条命中后仍归本规则）</h3>
              {entry.region.length === 0 ? (
                <div className="code-list">
                  <div className="line muted-text">无 —— 声明区域全部被前序规则夺走</div>
                </div>
              ) : (
                <div className="code-list">
                  {entry.region.map((g) => (
                    <div key={g.protocol} className="line">
                      <strong>{g.protocol}</strong> · {formatSize(g.size)} 条报文空间
                      <div className="muted-text" style={{ paddingLeft: 12 }}>
                        IP：{g.cidrs.join(', ')}
                      </div>
                      <div className="muted-text" style={{ paddingLeft: 12 }}>
                        端口：
                        {g.portRanges.map((r) => formatPortRange(r.start, r.end)).join(', ')}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {entry.shadowSources.length > 0 && (
            <div className="detail-block" style={{ marginTop: 14 }}>
              <h3>
                遮蔽来源（共 {entry.blockedCells} 个被遮蔽单元；
                {entry.collectiveCover ? '并集共同覆盖，无单一来源可独立完全遮蔽' : '按贡献排序'}）
              </h3>
              <div>
                {entry.shadowSources.map((s) => (
                  <div className="source-row" key={s.ruleIndex}>
                    <span className="src-idx">#{s.ruleIndex + 1}</span>
                    <span>{s.ruleName}</span>
                    <span className="muted-text">（{s.action}）</span>
                    <span className="spacer" />
                    <span className="muted-text">遮蔽 {s.cells} 个单元</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {entry.minExplanation && <MinExplanationBlock min={entry.minExplanation} />}

          {exemption && (
            <div style={{ marginTop: 14 }}>
              <ExemptionBlock exemption={exemption} />
            </div>
          )}

          <div className="detail-grid" style={{ marginTop: 14 }}>
            {entry.reachableExample && (
              <div className="detail-block">
                <h3>可达示例报文（实际命中本规则）</h3>
                <PacketLine packet={entry.reachableExample} />
              </div>
            )}
            {entry.shadowedExamples.length > 0 && (
              <div className="detail-block">
                <h3>遮蔽示例报文（实际命中的是前序规则）</h3>
                {entry.shadowedExamples.map((p, k) => (
                  <PacketLine key={k} packet={p} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function InvalidEntry({ entry }: { entry: AuditInvalidEntry }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="entry entry-invalid open">
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{entry.index + 1}</span>
        <span className="title">{entry.name}</span>
        <span className="badge invalid">非法 · 不参与分析</span>
      </div>
      {open && (
        <div className="entry-body">
          <ul className="error-list">
            {entry.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
          <div className="code-list" style={{ marginTop: 8 }}>
            <div className="line">CIDR：{String(entry.raw.cidr) || '（空）'}</div>
            <div className="line">
              源端口：{String(entry.raw.portStart)} – {String(entry.raw.portEnd)}
            </div>
            <div className="line">协议：{String(entry.raw.protocol) || '（空）'}</div>
            <div className="line">动作：{String(entry.raw.action) || '（空）'}</div>
          </div>
        </div>
      )}
    </div>
  )
}

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'issues', label: '仅问题' },
  { key: 'fully', label: '完全遮蔽' },
  { key: 'partial', label: '部分遮蔽' },
  { key: 'reachable', label: '可达' },
  { key: 'exempt-full', label: '已全部豁免' },
  { key: 'exempt-partial', label: '部分豁免' },
  { key: 'exempt-none', label: '未豁免待处理' },
  { key: 'disabled', label: '停用' },
  { key: 'invalid', label: '非法' },
]

export function AuditResults({
  report,
  exemptionReport,
}: {
  report: AuditReport
  exemptionReport?: ExemptionReport
}) {
  const [filter, setFilter] = useState<Filter>('all')

  const exemptionById = new Map<string, RuleExemption>()
  if (exemptionReport) {
    for (const e of exemptionReport.entries) {
      if (e.kind === 'rule') exemptionById.set(e.ruleId, e)
    }
  }

  const entries = report.entries.filter((e) => {
    if (filter === 'all') return true
    if (filter === 'invalid') return e.kind === 'invalid'
    if (filter === 'issues')
      return (
        e.kind === 'invalid' ||
        (e.kind === 'valid' && e.status !== 'reachable' && e.status !== 'disabled')
      )
    if (filter === 'reachable') return e.kind === 'valid' && e.status === 'reachable'
    if (filter === 'fully') return e.kind === 'valid' && e.status === 'fully-shadowed'
    if (filter === 'partial') return e.kind === 'valid' && e.status === 'partial-shadowed'
    if (filter === 'disabled') return e.kind === 'valid' && e.status === 'disabled'
    // 豁免状态筛选：只对存在遮蔽区域（完全 / 部分遮蔽）的规则生效
    if (
      filter === 'exempt-full' ||
      filter === 'exempt-partial' ||
      filter === 'exempt-none'
    ) {
      if (
        e.kind !== 'valid' ||
        (e.status !== 'fully-shadowed' && e.status !== 'partial-shadowed')
      ) {
        return false
      }
      const ex = exemptionById.get(e.id)
      if (!ex) return filter === 'exempt-none'
      if (filter === 'exempt-full') return ex.fullyExempt
      if (filter === 'exempt-partial') return !ex.fullyExempt && ex.exemptSize > 0
      return ex.exemptSize === 0
    }
    return true
  })

  return (
    <div>
      <div className="filter-bar">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            className={filter === f.key ? 'active' : ''}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>
      {entries.length === 0 && (
        <div className="notice info">当前筛选下没有规则。</div>
      )}
      {entries.map((entry) =>
        entry.kind === 'valid' ? (
          <ValidEntry
            key={`${entry.index}-${entry.id}`}
            entry={entry}
            exemption={exemptionById.get(entry.id)}
          />
        ) : (
          <InvalidEntry key={`${entry.index}-${entry.id}`} entry={entry} />
        ),
      )}
    </div>
  )
}
