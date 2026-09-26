import { useEffect, useMemo, useState } from 'react'
import {
  evaluateExceptions,
  expiryFromDatetimeLocal,
  expiryToDatetimeLocal,
  formatExpiry,
  ISSUE_TYPES,
  ISSUE_TYPE_TEXT,
  newExceptionInput,
  parseExceptionsJson,
  serializeExceptions,
} from './audit/exemption'
import type {
  ExceptionCoverage,
  ExceptionInput,
  ExemptionReport,
  InvalidException,
  RuleExemption,
} from './audit/exemption'
import type { AuditReport, RuleInput } from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
  auditReport: AuditReport
  exceptions: ExceptionInput[]
  setExceptions: (next: ExceptionInput[]) => void
}

const REASON_TEXT: Record<InvalidException['reason'], string> = {
  invalid: '非法 · 不参与豁免',
  expired: '已过期 · 不参与豁免',
  'rule-missing': '目标规则不存在',
  'rule-invalid': '目标规则非法',
  'rule-disabled': '目标规则已停用',
  'issue-mismatch': '问题类型不匹配',
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

/** 精确区域：协议 → 连续端口段 × 规范 CIDR（行式，互斥且完备） */
function RegionView({ regions }: { regions: RuleExemption['exemptRegions'] }) {
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

function PacketLine({
  packet,
  tag,
  tagClass,
  note,
}: {
  packet: NonNullable<RuleExemption['exemptRepresentative']>
  tag: string
  tagClass: 'reachable' | 'shadowed'
  note: string
}) {
  return (
    <div className="packet-box">
      <span className={`tag ${tagClass}`}>{tag}</span>
      <span className="mono">{formatPacket(packet)}</span>
      <span className="arrow-note">{note}</span>
      <CopyButton text={formatPacket(packet)} />
    </div>
  )
}

/** 单条有效例外的覆盖卡片 */
function CoverageView({ coverage }: { coverage: ExceptionCoverage }) {
  const expiryNote =
    coverage.expiresAtMs === null ? '永久有效' : `到期 ${formatExpiry(coverage.expiresAtText)}`
  return (
    <div className={`takeover-block ${coverage.noOverlap ? 'conflict-block' : ''}`}>
      <div className="takeover-head">
        <span className="action-pill">{ISSUE_TYPE_TEXT[coverage.issueType]}</span>
        <span className="mono">
          {coverage.cidrText} · 端口 {formatPortRange(coverage.portStart, coverage.portEnd)} ·{' '}
          {coverage.protocol}
        </span>
        {coverage.noOverlap ? (
          <span className="traffic-alert">与当前遮蔽区域无交集 · 不豁免任何报文</span>
        ) : (
          <span className="traffic-same">已豁免 {formatSize(coverage.coveredSize)}</span>
        )}
        <span className="spacer" />
        <span className="muted-text">{expiryNote}</span>
      </div>
      <div className="muted-text" style={{ marginBottom: 6 }}>说明：{coverage.notes}</div>
      {!coverage.noOverlap && coverage.representative && (
        <PacketLine
          packet={coverage.representative}
          tag="豁免代表报文"
          tagClass="reachable"
          note="该报文被此例外覆盖，标记为已豁免"
        />
      )}
      {!coverage.noOverlap && (
        <>
          <div className="goal-block-title">精确交集区域（例外范围 ∩ 实际遮蔽区域）</div>
          <RegionView regions={coverage.regions} />
        </>
      )}
    </div>
  )
}

/** 一条规则的豁免分解卡片 */
function RuleExemptionCard({ ex }: { ex: RuleExemption }) {
  const [open, setOpen] = useState(true)
  return (
    <div
      className={`entry ${
        ex.fullyExempt ? 'entry-exempt-full' : ex.exemptSize > 0 ? 'entry-exempt-partial' : 'entry-fully-shadowed'
      } ${open ? 'open' : ''}`}
    >
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{ex.ruleIndex + 1}</span>
        <span className="title">{ex.ruleName}</span>
        <span className="badge partial-shadowed">
          {ex.ruleStatus === 'fully-shadowed'
            ? ISSUE_TYPE_TEXT['fully-shadowed']
            : ISSUE_TYPE_TEXT['partial-shadowed']}
        </span>
        {ex.fullyExempt ? (
          <span className="badge exempt-badge">已全部豁免</span>
        ) : ex.exemptSize > 0 ? (
          <span className="badge exempt-partial-badge">部分豁免</span>
        ) : (
          <span className="badge muted">未豁免 · 待处理</span>
        )}
        <span className="spacer" />
        <span className="meta">
          已豁免 {formatSize(ex.exemptSize)} / 遮蔽 {formatSize(ex.blockedSize)}（
          {formatPercent(ex.exemptRatio)}） · 待处理 {formatSize(ex.pendingSize)}
        </span>
      </div>
      {open && (
        <div className="entry-body" onClick={(e) => e.stopPropagation()}>
          <div className="detail-grid">
            <div className="detail-block exempt-block-ok">
              <h3>已豁免区域（被有效例外覆盖的遮蔽单元并集）</h3>
              {ex.exemptSize === 0 ? (
                <div className="line muted-text">无 —— 没有任何有效例外覆盖该规则的遮蔽区域</div>
              ) : (
                <>
                  <div className="muted-text" style={{ marginBottom: 6 }}>
                    {formatSize(ex.exemptSize)} 条报文空间（{ex.exemptCells} 个原子单元，占遮蔽区域{' '}
                    {formatPercent(ex.exemptRatio)}）；多条例外重叠处按并集去重、不重复计数
                  </div>
                  {ex.exemptRepresentative && (
                    <PacketLine
                      packet={ex.exemptRepresentative}
                      tag="已豁免代表报文"
                      tagClass="reachable"
                      note="该报文无需再处理"
                    />
                  )}
                  <RegionView regions={ex.exemptRegions} />
                </>
              )}
            </div>

            <div className={`detail-block ${ex.pendingSize > 0 ? 'exempt-block-pending' : ''}`}>
              <h3>待处理区域（遮蔽区域减去豁免并集，仍计入审计问题）</h3>
              {ex.pendingSize === 0 ? (
                <div className="line muted-text">无 —— 遮蔽区域已被例外全部覆盖</div>
              ) : (
                <>
                  <div className="muted-text" style={{ marginBottom: 6 }}>
                    {formatSize(ex.pendingSize)} 条报文空间（{ex.pendingCells} 个原子单元）
                  </div>
                  {ex.pendingRepresentative && (
                    <PacketLine
                      packet={ex.pendingRepresentative}
                      tag="待处理代表报文"
                      tagClass="shadowed"
                      note={`看似属于 #${ex.ruleIndex + 1} ${ex.ruleName}，实际命中前序规则`}
                    />
                  )}
                  <RegionView regions={ex.pendingRegions} />
                </>
              )}
            </div>
          </div>

          {ex.coverages.length > 0 && (
            <div className="detail-block" style={{ marginTop: 14 }}>
              <h3>适用例外（共 {ex.coverages.length} 条，按实际覆盖大小排序）</h3>
              {ex.coverages.map((c) => (
                <CoverageView key={c.exceptionId} coverage={c} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/** 不参与豁免的例外条目（非法 / 过期 / 目标无效 / 问题不匹配） */
function InvalidExceptionRow({ entry }: { entry: InvalidException }) {
  return (
    <div className="except-row except-row-invalid">
      <span className="badge invalid">{REASON_TEXT[entry.reason]}</span>
      <span className="spacer" />
      <span className="muted-text">{entry.message}</span>
      {entry.errors.length > 0 && (
        <ul className="error-list" style={{ width: '100%', marginTop: 6 }}>
          {entry.errors.map((err, i) => (
            <li key={i}>{err}</li>
          ))}
        </ul>
      )}
      <div className="code-list" style={{ width: '100%', marginTop: 6 }}>
        <div className="line">
          目标 ruleId：{entry.ruleId || '（空）'} · 问题：
          {entry.issueType ? ISSUE_TYPE_TEXT[entry.issueType] : String(entry.issueType ?? '（空）')}
        </div>
        <div className="line">
          CIDR：{String(entry.cidr) || '（空）'} · 端口：{String(entry.portStart)}–
          {String(entry.portEnd)} · 协议：{String(entry.protocol) || '（空）'}
        </div>
        {String(entry.expiresAt) && <div className="line">到期时间原文：{String(entry.expiresAt)}</div>}
        {String(entry.notes) && <div className="line">说明：{String(entry.notes)}</div>}
      </div>
    </div>
  )
}

interface DraftState {
  editingId: string | null // null = 新增
  form: ExceptionInput
}

export function ExceptionPanel({ rules, auditReport, exceptions, setExceptions }: Props) {
  // 每分钟重估一次，使跨过到期时刻的例外自动转为「已过期」
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), 60_000)
    return () => clearInterval(timer)
  }, [])

  // 评估随规则与清单自动重算；tick 变化（每分钟）同样刷新到期状态
  const report: ExemptionReport = useMemo(
    () => evaluateExceptions(rules, exceptions),
    [rules, exceptions, tick],
  )

  const [draft, setDraft] = useState<DraftState | null>(null)
  const [showInvalidOnly, setShowInvalidOnly] = useState(false)

  const validRulesById = useMemo(() => {
    const m = new Map<string, RuleInput>()
    rules.forEach((r) => m.set(r.id, r))
    return m
  }, [rules])

  // 规则 id -> 当前审计条目（序号随调序 / 增删实时变化，展示一律取审计报告中的最新序号）
  const auditEntryById = useMemo(() => {
    const m = new Map(auditReport.entries.map((e) => [e.id, e]))
    return m
  }, [auditReport])

  // 清单条目 -> 评估状态（用于行内徽章）
  const invalidById = useMemo(() => {
    const m = new Map<string, InvalidException>()
    for (const e of report.entries) {
      if (e.kind === 'invalid-exception') m.set(e.id, e)
    }
    return m
  }, [report])

  const coverageById = useMemo(() => {
    const m = new Map<string, { ruleName: string; coverage: ExceptionCoverage }>()
    for (const e of report.entries) {
      if (e.kind !== 'rule') continue
      for (const c of e.coverages) {
        m.set(c.exceptionId, { ruleName: e.ruleName, coverage: c })
      }
    }
    return m
  }, [report])

  const patch = (p: Partial<ExceptionInput>) =>
    setDraft((d) => (d ? { ...d, form: { ...d.form, ...p } } : d))

  const startAdd = () => {
    // 默认选中第一条有遮蔽问题的规则，并预填其问题类型与声明范围
    let target: { id: string; issueType: 'fully-shadowed' | 'partial-shadowed' } | null = null
    for (const entry of auditReport.entries) {
      if (
        entry.kind === 'valid' &&
        (entry.status === 'fully-shadowed' || entry.status === 'partial-shadowed')
      ) {
        target = { id: entry.id, issueType: entry.status }
        break
      }
    }
    const form = newExceptionInput(
      target?.id ?? rules[0]?.id ?? '',
      target?.issueType ?? 'fully-shadowed',
    )
    const targetRule = target ? validRulesById.get(target.id) : undefined
    if (targetRule) {
      form.cidr = targetRule.cidr
      form.portStart = targetRule.portStart
      form.portEnd = targetRule.portEnd
      form.protocol = targetRule.protocol
    }
    setDraft({ editingId: null, form })
  }

  const startEdit = (input: ExceptionInput) =>
    setDraft({ editingId: input.id, form: { ...input } })

  const saveDraft = () => {
    if (!draft) return
    if (draft.editingId === null) {
      setExceptions([...exceptions, draft.form])
    } else {
      setExceptions(exceptions.map((e) => (e.id === draft.editingId ? draft.form : e)))
    }
    setDraft(null)
  }

  const remove = (id: string) => {
    if (confirm('删除该条例外？')) setExceptions(exceptions.filter((e) => e.id !== id))
  }

  const downloadJson = () => {
    const blob = new Blob([serializeExceptions(exceptions)], {
      type: 'application/json',
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-exceptions-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const importFile = (file: File) => {
    const reader = new FileReader()
    reader.onload = () => {
      const text = String(reader.result ?? '')
      const { exceptions: parsed, errors } = parseExceptionsJson(text)
      if (parsed.length === 0) {
        alert(errors.length ? errors.join('\n') : '未找到任何例外条目')
        return
      }
      if (confirm(`解析到 ${parsed.length} 条例外。确定替换当前全部例外？（取消则追加）`)) {
        setExceptions(parsed)
      } else {
        setExceptions([...exceptions, ...parsed])
      }
      if (errors.length > 0) alert(errors.join('\n'))
    }
    reader.readAsText(file)
  }

  const st = report.stats
  const ruleEntries = report.entries.filter(
    (e): e is RuleExemption => e.kind === 'rule',
  )
  const invalidEntries = report.entries.filter(
    (e): e is InvalidException => e.kind === 'invalid-exception',
  )

  const draftRule = draft ? validRulesById.get(draft.form.ruleId) : undefined

  return (
    <div className="panel exception-panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>审计例外清单</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          为指定规则的遮蔽问题登记例外；系统把例外范围与<strong>实际遮蔽区域</strong>
          做精确交集，仅被覆盖且未过期的部分标记「已豁免」，剩余仍列「待处理」。
          例外不改变审计结论；规则编辑后自动重算。
        </span>
      </div>

      <div className="exception-toolbar">
        <button className="primary" onClick={startAdd} disabled={rules.length === 0}>
          ＋ 登记例外
        </button>
        <button onClick={downloadJson} disabled={exceptions.length === 0}>
          导出例外 JSON
        </button>
        <label className="file-btn">
          导入本地 JSON 文件
          <input
            type="file"
            accept=".json,application/json"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) importFile(f)
              e.target.value = ''
            }}
          />
        </label>
        <button
          className="ghost danger"
          disabled={exceptions.length === 0}
          onClick={() => {
            if (confirm('清空全部例外？')) setExceptions([])
          }}
        >
          清空例外
        </button>
      </div>

      <div className="stats">
        <div className="stat-card ok">
          <div className="label">有效例外</div>
          <div className="value" style={{ fontSize: 16 }}>{st.activeCount}</div>
          {st.noOverlapCount > 0 && (
            <div className="label">其中 {st.noOverlapCount} 条与遮蔽区域无交集</div>
          )}
        </div>
        <div className="stat-card danger">
          <div className="label">非法 / 已过期</div>
          <div className="value" style={{ fontSize: 16 }}>
            {st.invalidCount + st.expiredCount}
          </div>
        </div>
        <div className="stat-card warn">
          <div className="label">目标失效 / 类型不匹配</div>
          <div className="value" style={{ fontSize: 16 }}>
            {st.targetBadCount + st.mismatchCount}
          </div>
        </div>
        <div className="stat-card ok">
          <div className="label">已全部豁免规则</div>
          <div className="value" style={{ fontSize: 16 }}>
            {st.fullyExemptRuleCount}
            <span className="muted-text"> / {st.issueRuleCount}</span>
          </div>
        </div>
        <div className="stat-card">
          <div className="label">已豁免报文空间</div>
          <div className="value" style={{ fontSize: 15 }}>{formatSize(st.totalExemptSize)}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">待处理报文空间</div>
          <div className="value" style={{ fontSize: 15 }}>{formatSize(st.totalPendingSize)}</div>
        </div>
      </div>

      {/* 新增 / 编辑表单 */}
      {draft && (
        <div className="exception-form">
          <h3>{draft.editingId === null ? '登记新例外' : '编辑例外'}</h3>
          <div className="exception-form-grid">
            <label>
              <span>适用规则 *</span>
              <select
                value={draft.form.ruleId}
                onChange={(e) => patch({ ruleId: e.target.value })}
              >
                <option value="">（请选择规则）</option>
                {auditReport.entries.map((entry) => {
                  if (entry.kind !== 'valid') {
                    return (
                      <option key={entry.id} value={entry.id} disabled>
                        #{entry.index + 1} {entry.name}（非法）
                      </option>
                    )
                  }
                  const disabledSuffix = entry.status === 'disabled' ? '（停用）' : ''
                  return (
                    <option key={entry.id} value={entry.id}>
                      #{entry.index + 1} {entry.name}
                      {disabledSuffix} · {entry.status === 'fully-shadowed'
                        ? '完全遮蔽'
                        : entry.status === 'partial-shadowed'
                          ? '部分遮蔽'
                          : entry.status === 'reachable'
                            ? '可达'
                            : entry.status}
                    </option>
                  )
                })}
              </select>
            </label>
            <label>
              <span>问题类型 *</span>
              <select
                value={draft.form.issueType}
                onChange={(e) => patch({ issueType: e.target.value })}
              >
                {ISSUE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {ISSUE_TYPE_TEXT[t]}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>适用 CIDR *</span>
              <input
                value={draft.form.cidr}
                onChange={(e) => patch({ cidr: e.target.value })}
                spellCheck={false}
                placeholder="192.168.1.0/24"
              />
            </label>
            <label>
              <span>端口区间 *</span>
              <div className="port-cell">
                <input
                  value={draft.form.portStart}
                  onChange={(e) => patch({ portStart: e.target.value })}
                />
                <span className="muted-text">–</span>
                <input
                  value={draft.form.portEnd}
                  onChange={(e) => patch({ portEnd: e.target.value })}
                />
              </div>
            </label>
            <label>
              <span>协议 *</span>
              <select
                value={draft.form.protocol}
                onChange={(e) => patch({ protocol: e.target.value })}
              >
                {['ANY', 'TCP', 'UDP'].map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </label>
            <label>
              <span>到期时间（UTC；留空 = 永久）</span>
              <input
                type="datetime-local"
                value={expiryToDatetimeLocal(draft.form.expiresAt)}
                onChange={(e) =>
                  patch({ expiresAt: expiryFromDatetimeLocal(e.target.value) })
                }
              />
            </label>
            <label className="exception-form-notes">
              <span>说明 *</span>
              <input
                value={draft.form.notes}
                onChange={(e) => patch({ notes: e.target.value })}
                placeholder="如：已知冗余，迁移期保留"
              />
            </label>
          </div>
          {draftRule && (
            <div className="muted-text" style={{ marginBottom: 8 }}>
              提示：例外仅豁免该规则<strong>实际被遮蔽区域</strong>与例外范围的交集；
              规则声明区域为 {draftRule.cidr} · 端口 {String(draftRule.portStart)}–
              {String(draftRule.portEnd)} · {draftRule.protocol}。
            </div>
          )}
          <div className="safe-action-row">
            <button className="primary" onClick={saveDraft}>保存例外</button>
            <button onClick={() => setDraft(null)}>取消</button>
          </div>
        </div>
      )}

      {/* 例外清单表 */}
      {exceptions.length > 0 && (
        <>
          <h3 className="reorder-section-title">例外清单（{exceptions.length} 条）</h3>
          <div style={{ overflowX: 'auto' }}>
            <table className="rule-table exception-table">
              <thead>
                <tr>
                  <th>目标规则</th>
                  <th>问题类型</th>
                  <th>适用范围</th>
                  <th>到期</th>
                  <th>状态</th>
                  <th>说明</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {exceptions.map((input) => {
                  const bad = invalidById.get(input.id)
                  const covered = coverageById.get(input.id)
                  const targetEntry = auditEntryById.get(input.ruleId)
                  return (
                    <tr
                      key={input.id}
                      className={bad ? 'except-row-invalid' : ''}
                    >
                      <td>
                        {targetEntry
                          ? `#${targetEntry.index + 1} ${targetEntry.name || '（未命名）'}`
                          : <span className="muted-text">{input.ruleId || '（空）'}</span>}
                      </td>
                      <td>
                        {ISSUE_TYPE_TEXT[
                          (input.issueType as keyof typeof ISSUE_TYPE_TEXT)
                        ] ?? input.issueType}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {input.cidr}
                        <br />
                        {String(input.portStart)}–{String(input.portEnd)} · {input.protocol}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        {formatExpiry(input.expiresAt)}
                      </td>
                      <td>
                        {bad ? (
                          <span className="badge invalid" title={bad.message}>
                            {REASON_TEXT[bad.reason]}
                          </span>
                        ) : covered?.coverage.noOverlap ? (
                          <span className="badge exempt-partial-badge">无交集</span>
                        ) : (
                          <span className="badge exempt-badge">
                            豁免 {formatSize(covered?.coverage.coveredSize ?? 0)}
                          </span>
                        )}
                      </td>
                      <td style={{ maxWidth: 220, fontSize: 12 }}>{input.notes}</td>
                      <td>
                        <div className="row-actions">
                          <button onClick={() => startEdit(input)}>编辑</button>
                          <button className="danger ghost" onClick={() => remove(input.id)}>
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
        </>
      )}

      {invalidEntries.length > 0 && (
        <>
          <h3 className="reorder-section-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            不参与豁免的例外（{invalidEntries.length} 条）
            <button className="copy-mini" onClick={() => setShowInvalidOnly((v) => !v)}>
              {showInvalidOnly ? '收起明细' : '展开明细'}
            </button>
          </h3>
          {showInvalidOnly &&
            invalidEntries.map((entry) => (
              <InvalidExceptionRow key={entry.id} entry={entry} />
            ))}
        </>
      )}

      {/* 按规则的豁免分解 */}
      <h3 className="reorder-section-title">
        遮蔽区域豁免分解（{ruleEntries.length} 条有遮蔽问题的规则；
        已豁免 {formatSize(st.totalExemptSize)} · 待处理 {formatSize(st.totalPendingSize)}）
      </h3>
      {ruleEntries.length === 0 ? (
        <div className="notice info" style={{ marginBottom: 0 }}>
          当前规则集没有遮蔽问题（完全遮蔽 / 部分遮蔽），例外无需生效。
        </div>
      ) : (
        ruleEntries.map((entry) => (
          <RuleExemptionCard key={entry.ruleId} ex={entry} />
        ))
      )}
    </div>
  )
}
