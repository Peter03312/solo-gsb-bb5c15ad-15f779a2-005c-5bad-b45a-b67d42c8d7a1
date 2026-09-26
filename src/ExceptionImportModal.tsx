import { useState } from 'react'

interface ImportExceptionsModalProps {
  onClose: () => void
  onImport: (text: string, mode: 'replace' | 'append') => string[]
}

const EXAMPLE_JSON = `{
  "format": "audit-exceptions",
  "version": 1,
  "exceptions": [
    {
      "ruleId": "demo-3",
      "issueType": "fully-shadowed",
      "cidr": "192.168.1.0/24",
      "portStart": 22,
      "portEnd": 22,
      "protocol": "TCP",
      "expiresAt": "2026-12-31T23:59:59Z",
      "notes": "已知冗余拦截，迁移期保留"
    }
  ]
}`

export function ImportExceptionsModal({ onClose, onImport }: ImportExceptionsModalProps) {
  const [text, setText] = useState('')
  const [errors, setErrors] = useState<string[]>([])

  const doImport = (mode: 'replace' | 'append') => {
    const errs = onImport(text, mode)
    if (errs.length > 0) setErrors(errs)
    else onClose()
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">粘贴 JSON 导入审计例外</div>
        <div className="modal-body">
          <div className="notice info" style={{ marginTop: 0 }}>
            支持 <span className="mono">{'{ exceptions: [...] }'}</span>（本工具导出格式）
            或直接粘贴数组 <span className="mono">[{`{...}`}]</span>。字段：
            <span className="mono"> ruleId, issueType, cidr, portStart, portEnd, protocol, expiresAt, notes</span>
            。<strong>非法或过期条目不阻止导入</strong>，会保留在清单中并明确标注、不参与豁免。
            ruleId 可在规则编辑表中查看（导出规则 JSON 时包含 id 字段）。
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={EXAMPLE_JSON}
            spellCheck={false}
          />
          {errors.length > 0 && (
            <div className="notice error" style={{ marginTop: 10 }}>
              {errors.map((e, i) => (
                <div key={i}>• {e}</div>
              ))}
            </div>
          )}
        </div>
        <div className="modal-footer">
          <button onClick={onClose}>取消</button>
          <button onClick={() => doImport('append')}>追加到现有例外</button>
          <button className="primary" onClick={() => doImport('replace')}>
            替换全部例外
          </button>
        </div>
      </div>
    </div>
  )
}
