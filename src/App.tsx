import { useEffect, useMemo, useState } from 'react'
import { RuleTable } from './RuleTable'
import { AuditResults } from './AuditResults'
import { GoalVerify } from './GoalVerify'
import { SimplifyPanel } from './SimplifyPanel'
import { RegressionPanel } from './RegressionPanel'
import { AttributionPanel } from './AttributionPanel'
import { ExceptionPanel } from './ExceptionPanel'
import { SnapshotPanel } from './SnapshotPanel'
import { TandemPanel } from './TandemPanel'
import { ImportModal, ExportModal } from './Modals'
import { ImportExceptionsModal } from './ExceptionImportModal'
import { ReorderPreviewModal } from './ReorderPreviewModal'
import { audit, exportReport, newRuleInput, parseRulesJson } from './audit/engine'
import { movedRules } from './audit/reorder'
import { parseExceptionsJson, serializeExceptions, evaluateExceptions } from './audit/exemption'
import type { ExceptionInput } from './audit/exemption'
import type { RuleInput } from './audit/types'
import { createDemoRules } from './defaultRules'
import { formatSize } from './format'
import './styles.css'

interface PendingReorder {
  candidate: RuleInput[]
}

export default function App() {
  const [rules, setRules] = useState<RuleInput[]>(() => createDemoRules())
  const [exceptions, setExceptions] = useState<ExceptionInput[]>([])
  const [showImport, setShowImport] = useState(false)
  const [showExport, setShowExport] = useState(false)
  const [showImportExceptions, setShowImportExceptions] = useState(false)
  const [pendingReorder, setPendingReorder] = useState<PendingReorder | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const report = useMemo(() => audit(rules), [rules])
  const exportJson = useMemo(() => exportReport(report), [report])
  // 每分钟重估一次，使跨过到期时刻的例外在结果区也自动转为过期 / 待处理
  const [tick, setTick] = useState(0)
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), 60_000)
    return () => clearInterval(timer)
  }, [])
  // 豁免重算随规则编辑 / 例外清单变更自动进行；审计结论本身不变
  const exemptionReport = useMemo(
    () => evaluateExceptions(rules, exceptions),
    [rules, exceptions, tick],
  )

  const patchRule = (index: number, patch: Partial<RuleInput>) =>
    setRules((rs) => rs.map((r, i) => (i === index ? { ...r, ...patch } : r)))

  const removeRule = (index: number) =>
    setRules((rs) => rs.filter((_, i) => i !== index))

  // 无损精简按规则 id 删除（分析结果可能来自编辑前的快照，不能按下标删）
  const removeRuleById = (id: string) =>
    setRules((rs) => rs.filter((r) => r.id !== id))

  const duplicateRule = (index: number) =>
    setRules((rs) => {
      const copy: RuleInput = { ...rs[index], id: Math.random().toString(36).slice(2, 10) }
      const next = [...rs]
      next.splice(index + 1, 0, copy)
      return next
    })

  const addRule = () => setRules((rs) => [...rs, newRuleInput(rs.length)])

  // 拖拽只产生候选顺序：rules 不立即改动，先弹出影响预览
  const requestReorder = (from: number, to: number) => {
    if (from === to) return
    setPendingReorder({ candidate: movedRules(rules, from, to) })
  }

  const confirmReorder = () => {
    if (!pendingReorder) return
    setRules(pendingReorder.candidate)
    setPendingReorder(null)
    setNotice('候选顺序已应用，审计结果已按新顺序刷新。')
    setTimeout(() => setNotice(null), 4000)
  }

  const cancelReorder = () => setPendingReorder(null)

  const handleImport = (text: string, mode: 'replace' | 'append'): string[] => {
    const { rules: parsed, errors } = parseRulesJson(text)
    if (parsed.length === 0) return errors.length ? errors : ['未找到任何规则']
    setRules((rs) => (mode === 'replace' ? parsed : [...rs, ...parsed]))
    const ok: string[] = []
    if (errors.length > 0) {
      setNotice(`导入 ${parsed.length} 条；${errors.length} 条记录有提示：${errors[0]}${errors.length > 1 ? ' 等' : ''}`)
      setTimeout(() => setNotice(null), 5000)
    }
    return ok
  }

  // 例外清单导入：非法 / 过期条目不阻止导入（保留在清单中明确标注），
  // 结构 / JSON 错误通过返回值在弹窗内提示
  const handleImportExceptions = (text: string, mode: 'replace' | 'append'): string[] => {
    const { exceptions: parsed, errors } = parseExceptionsJson(text)
    if (parsed.length === 0) return errors.length ? errors : ['未找到任何例外条目']
    setExceptions((prev) => (mode === 'replace' ? parsed : [...prev, ...parsed]))
    if (errors.length > 0) {
      setNotice(`导入 ${parsed.length} 条例外；提示：${errors[0]}${errors.length > 1 ? ' 等' : ''}`)
      setTimeout(() => setNotice(null), 5000)
    }
    return []
  }

  const exportExceptionsJson = () => serializeExceptions(exceptions)

  const s = report.stats

  return (
    <div>
      <h1>首命中规则审计台</h1>
      <p className="subtitle">
        基于「自上而下、首条匹配」语义，精确计算每条 IPv4 CIDR × 端口区间 × 协议规则的实际可达区域；
        识别完全遮蔽、部分遮蔽与多规则共同覆盖，并给出可复现的示例报文与遮蔽来源。全部计算在浏览器本地完成。
      </p>

      <div className="toolbar">
        <button className="primary" onClick={addRule}>＋ 新增规则</button>
        <button onClick={() => setShowImport(true)}>粘贴 JSON 导入</button>
        <button onClick={() => setShowExport(true)}>导出审计结果</button>
        <button
          onClick={() => {
            const blob = new Blob([JSON.stringify(rules, null, 2)], {
              type: 'application/json',
            })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = 'rules.json'
            a.click()
            URL.revokeObjectURL(url)
          }}
        >
          导出规则（可再导入）
        </button>
        <button onClick={() => setShowImportExceptions(true)}>
          导入审计例外 JSON
        </button>
        <button
          onClick={() => {
            const blob = new Blob([exportExceptionsJson()], {
              type: 'application/json',
            })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = 'audit-exceptions.json'
            a.click()
            URL.revokeObjectURL(url)
          }}
          disabled={exceptions.length === 0}
        >
          导出审计例外
        </button>
        <button
          className="danger ghost"
          onClick={() => {
            if (confirm('清空全部规则？')) setRules([])
          }}
        >
          清空
        </button>
        <button
          className="ghost"
          onClick={() => setRules(createDemoRules())}
        >
          恢复演示规则
        </button>
      </div>

      {notice && <div className="notice info">{notice}</div>}

      <div className="stats">
        <div className="stat-card">
          <div className="label">规则总数</div>
          <div className="value">{s.total}</div>
        </div>
        <div className="stat-card ok">
          <div className="label">完全可达</div>
          <div className="value">{s.reachable}</div>
        </div>
        <div className="stat-card warn">
          <div className="label">部分遮蔽</div>
          <div className="value">{s.partial}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">完全遮蔽</div>
          <div className="value">{s.fullyShadowed}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">非法（不参与分析）</div>
          <div className="value">{s.invalid}</div>
        </div>
        <div className="stat-card">
          <div className="label">停用（不参与分析）</div>
          <div className="value">{s.disabled}</div>
        </div>
        <div className="stat-card">
          <div className="label">有效 / 声明报文空间</div>
          <div className="value" style={{ fontSize: 14 }}>
            {formatSize(s.totalEffectiveSize)}
            <span className="muted-text"> / {formatSize(s.totalDeclaredSize)}</span>
          </div>
        </div>
      </div>

      <RuleTable
        rules={rules}
        entries={report.entries}
        onChange={patchRule}
        onRemove={removeRule}
        onDuplicate={duplicateRule}
        onReorder={requestReorder}
        onAdd={addRule}
      />

      <div className="section-gap">
        <GoalVerify rules={rules} />
      </div>

      <div className="section-gap">
        <SimplifyPanel rules={rules} onDeleteRule={removeRuleById} />
      </div>

      <div className="section-gap">
        <RegressionPanel rules={rules} />
      </div>

      <div className="section-gap">
        <AttributionPanel rules={rules} />
      </div>

      <div className="section-gap">
        <ExceptionPanel
          rules={rules}
          auditReport={report}
          exceptions={exceptions}
          setExceptions={setExceptions}
        />
      </div>

      <div className="section-gap">
        <SnapshotPanel rules={rules} />
      </div>

      <div className="section-gap">
        <TandemPanel rules={rules} />
      </div>

      <div className="section-gap">
        <h2>审计结果</h2>
        <p className="legend" style={{ marginTop: -6, marginBottom: 10 }}>
          遮蔽仅考虑位于其上方（更早匹配）的规则；「共同覆盖」表示没有任何单条规则能独立遮蔽全部区域，
          需多条规则的并集才会使其失效。点击条目可展开可达区域、遮蔽来源与示例报文。
          「审计例外清单」中的有效例外仅在此额外标注豁免状态，<strong>不改变下列审计结论</strong>。
        </p>
        {rules.length === 0 ? (
          <div className="notice info">
            还没有规则。点击「新增规则」或「粘贴 JSON 导入」开始。
          </div>
        ) : (
          <AuditResults report={report} exemptionReport={exemptionReport} />
        )}
      </div>

      {showImport && (
        <ImportModal
          onClose={() => setShowImport(false)}
          onImport={handleImport}
        />
      )}
      {showExport && (
        <ExportModal json={exportJson} onClose={() => setShowExport(false)} />
      )}
      {showImportExceptions && (
        <ImportExceptionsModal
          onClose={() => setShowImportExceptions(false)}
          onImport={handleImportExceptions}
        />
      )}
      {pendingReorder && (
        <ReorderPreviewModal
          current={rules}
          candidate={pendingReorder.candidate}
          onConfirm={confirmReorder}
          onCancel={cancelReorder}
        />
      )}
    </div>
  )
}
