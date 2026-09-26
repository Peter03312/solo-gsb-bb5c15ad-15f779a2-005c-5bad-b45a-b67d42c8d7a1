import { useState } from 'react'

interface ImportModalProps {
  onClose: () => void
  onImport: (text: string, mode: 'replace' | 'append') => string[]
}

const EXAMPLE_JSON = `[
  {
    "name": "允许内网 Web",
    "cidr": "10.0.0.0/8",
    "portStart": 80,
    "portEnd": 443,
    "protocol": "TCP",
    "action": "allow"
  },
  {
    "name": "拒绝其余全部",
    "cidr": "0.0.0.0/0",
    "portStart": 0,
    "portEnd": 65535,
    "protocol": "ANY",
    "action": "deny"
  }
]`

export function ImportModal({ onClose, onImport }: ImportModalProps) {
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
        <div className="modal-header">粘贴 JSON 导入规则</div>
        <div className="modal-body">
          <div className="notice info" style={{ marginTop: 0 }}>
            支持数组 <span className="mono">[{`{...}`}]</span>、
            <span className="mono"> {'{ rules: [...] }'}</span> 或本工具导出的审计报告（
            <span className="mono">{'{ entries: [...] }'}</span>）。字段：
            <span className="mono"> name, cidr, portStart, portEnd, protocol, action</span>
            。非法 CIDR / 端口不会中断导入，而是保留在列表中并标记为不参与分析。
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
          <button onClick={() => doImport('append')}>追加到现有规则</button>
          <button className="primary" onClick={() => doImport('replace')}>
            替换全部规则
          </button>
        </div>
      </div>
    </div>
  )
}

interface ExportModalProps {
  json: string
  onClose: () => void
}

export function ExportModal({ json, onClose }: ExportModalProps) {
  const [copied, setCopied] = useState(false)

  const download = () => {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">导出审计结果（JSON）</div>
        <div className="modal-body">
          <pre className="json-preview">{json}</pre>
        </div>
        <div className="modal-footer">
          <button onClick={onClose}>关闭</button>
          <button
            onClick={async () => {
              await navigator.clipboard.writeText(json)
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            }}
          >
            {copied ? '已复制到剪贴板' : '复制 JSON'}
          </button>
          <button className="primary" onClick={download}>
            下载 .json
          </button>
        </div>
      </div>
    </div>
  )
}
