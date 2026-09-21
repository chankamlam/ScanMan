import { useEffect, useState } from 'react'
import { Alert, Spin } from 'antd'

import { loadReport } from './api'
import type { FileResult, FunctionInfo, ScanReport } from './types'
import { Ledger } from './components/Ledger'
import { RiskStrip } from './components/RiskStrip'
import { FileTable } from './components/FileTable'
import { FunctionDetail } from './components/FunctionDetail'

/** 选中项的稳定键，谱带和表格靠它互通。 */
export function selKey(file: string, fn: FunctionInfo): string {
  return `${file}::${fn.name}::${fn.start_line}`
}

export default function App() {
  const [report, setReport] = useState<ScanReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [sel, setSel] = useState<{ file: string; fn: FunctionInfo } | null>(null)

  useEffect(() => {
    loadReport()
      .then(setReport)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const pick = (file: string, fn: FunctionInfo) => setSel({ file, fn })

  return (
    <div style={{ minHeight: '100vh', background: 'var(--paper)' }}>
      <Masthead report={report} />

      {loading && (
        <div style={{ textAlign: 'center', padding: '120px 0' }}>
          <Spin size="large" />
          <div className="eyebrow" style={{ marginTop: 12 }}>
            正在读取扫描报告
          </div>
        </div>
      )}

      {error && (
        <div style={{ padding: 20 }}>
          <LoadError message={error} />
        </div>
      )}

      {report && (
        <>
          {report.threshold !== null && (
            <RiskStrip
              files={report.files}
              threshold={report.threshold}
              selectedKey={sel ? selKey(sel.file, sel.fn) : undefined}
              onSelect={pick}
            />
          )}

          <Ledger report={report} />

          <main style={{ padding: '0 20px 48px', maxWidth: 1560, margin: '0 auto' }}>
            <FileTable files={report.files} selected={sel} onSelect={pick} />

            {sel && (
              <section style={{ marginTop: 20 }}>
                <FunctionPanel
                  file={sel.file}
                  fn={sel.fn}
                  files={report.files}
                  threshold={report.threshold}
                  onClose={() => setSel(null)}
                />
              </section>
            )}

            {report.skipped.length > 0 && <Skipped report={report} />}
          </main>
        </>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ 页眉 */

/**
 * 页眉只做两件事：说清这是什么，以及这次扫描的对象是谁。
 * 不放装饰 —— 下面那条谱带才是主角。
 */
function Masthead({ report }: { report: ScanReport | null }) {
  return (
    <header
      style={{
        background: 'var(--surface)',
        borderBottom: '1px solid var(--rule)',
        padding: '16px 20px',
        display: 'flex',
        alignItems: 'flex-end',
        gap: 16,
        flexWrap: 'wrap',
      }}
    >
      {/* 标记：一个方形加缺口，像被"扫描"过一样 */}
      <svg width="26" height="26" viewBox="0 0 26 26" aria-hidden style={{ flexShrink: 0 }}>
        <rect x="1.5" y="1.5" width="23" height="23" rx="2" fill="none" stroke="var(--ink)" strokeWidth="2" />
        <path d="M7 13.5 L11.5 18 L19 8" fill="none" stroke="var(--flag)" strokeWidth="2.4"
              strokeLinecap="square" />
      </svg>

      <div>
        <h1
          style={{
            margin: 0,
            fontSize: 19,
            fontWeight: 600,
            letterSpacing: '-0.01em',
            lineHeight: 1.2,
          }}
        >
          代码漏洞扫描报告
        </h1>
        <div className="mono" style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 3 }}>
          ScanMan
          {report && (
            <>
              {' · '}
              <span title={report.root}>{report.root.replace(/\\/g, '/').split('/').filter(Boolean).slice(-2).join('/')}</span>
              {' · '}
              {new Date(report.generated_at).toLocaleString('zh-CN', { hour12: false })}
            </>
          )}
        </div>
      </div>
    </header>
  )
}

/* -------------------------------------------------------------- 详情面板 */

/**
 * 单个函数的完整分析。
 *
 * 左边是**真实行号的源码**（行号来自报告里的 `start_line`，不是从 1 数起的
 * 显示序号），右边是判定依据。这个左右结构本身就是"报告"的语义：
 * 左边是证据，右边是结论。
 */
function FunctionPanel({
  file,
  fn,
  files,
  threshold,
  onClose,
}: {
  file: string
  fn: FunctionInfo
  files: FileResult[]
  threshold: number | null
  onClose: () => void
}) {
  const fr = files.find((f) => f.path === file)
  return (
    <div className="panel">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: '11px 16px',
          borderBottom: '1px solid var(--rule)',
          flexWrap: 'wrap',
        }}
      >
        <span className="eyebrow">函数详情</span>
        <span className="mono" style={{ fontSize: 13, fontWeight: 500 }}>
          {fn.name}
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          {file}:{fn.start_line}–{fn.end_line}
        </span>
        <Verdict fn={fn} />
        <span style={{ flex: 1 }} />
        <button
          onClick={onClose}
          style={{
            border: 'none',
            background: 'none',
            color: 'var(--signal)',
            cursor: 'pointer',
            fontSize: 12,
            padding: '2px 6px',
          }}
        >
          收起
        </button>
      </div>
      <div style={{ padding: 16 }}>
        <FunctionDetail
          fn={fn}
          file={file}
          language={fr?.language ?? fn.language}
          threshold={threshold}
        />
      </div>
    </div>
  )
}

function Verdict({ fn }: { fn: FunctionInfo }) {
  if (!('verdict' in fn)) {
    return <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>未检测</span>
  }
  const vul = fn.verdict === 'vulnerable'
  return (
    <span
      className="mono"
      style={{
        fontSize: 11,
        padding: '1px 7px',
        borderRadius: 2,
        background: vul ? 'var(--flag-bg)' : 'var(--ok-bg)',
        color: vul ? 'var(--flag)' : 'var(--ok)',
        fontWeight: 500,
        letterSpacing: '0.02em',
      }}
    >
      {vul ? '有漏洞' : '安全'}
    </span>
  )
}

/* ------------------------------------------------------------------ 其他 */

function LoadError({ message }: { message: string }) {
  return (
    <Alert
      type="error"
      showIcon
      message="加载扫描报告失败"
      description={
        <div>
          <p style={{ marginBottom: 8 }}><code>{message}</code></p>
          <p style={{ marginBottom: 4 }}>先在项目根目录跑一次扫描，把结果放到 <code>web/public/sample_report.json</code>：</p>
          <pre style={{ background: 'var(--surface-2)', padding: 10, borderRadius: 3, fontSize: 12, overflowX: 'auto', margin: 0 }}>
{`python scripts/scan_project.py demo_verified/ \\
    --checkpoint outputs/merged_detection_codebert/best \\
    --classifier outputs/merged_top27_codebert_e20/best \\
    --output web/public/sample_report.json`}
          </pre>
        </div>
      }
    />
  )
}

function Skipped({ report }: { report: ScanReport }) {
  return (
    <section className="panel" style={{ marginTop: 20, padding: 16 }}>
      <div className="eyebrow" style={{ marginBottom: 8 }}>
        跳过的文件 · {report.skipped.length}
      </div>
      {report.skipped.slice(0, 30).map((it) => (
        <div key={it.path} className="mono" style={{ fontSize: 12, lineHeight: 1.7 }}>
          <span style={{ color: 'var(--ink-2)' }}>{it.path}</span>
          <span style={{ color: 'var(--ink-3)', margin: '0 8px' }}>·</span>
          <span style={{ color: 'var(--flag)' }}>{it.reason}</span>
        </div>
      ))}
    </section>
  )
}
