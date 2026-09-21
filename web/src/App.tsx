import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert } from 'antd'

import {
  ApiError,
  loadHealth,
  loadSampleReport,
  readFileBytes,
  runScan,
  type HealthInfo,
  type PendingFile,
  type UploadReceipt,
} from './api'
import type { FunctionInfo, ScanReport } from './types'
import { buildRows, rowsFromReport, type FileRow } from './rows'
import { Header } from './components/Header'
import { Sidebar } from './components/Sidebar'
import { Overview } from './components/Overview'
import { FunctionList } from './components/FunctionList'
import { FunctionDetail } from './components/FunctionDetail'
import { ProbHistogram } from './components/charts/ProbHistogram'
import { FileRiskRanking } from './components/charts/FileRiskRanking'
import { CweDistribution } from './components/charts/CweDistribution'
import { RiskHeatmap } from './components/charts/RiskHeatmap'
import { shortPath } from './format'

/** 与后端 `serve.py` 的 MAX_FILE_BYTES 对齐。 */
const MAX_FILE_BYTES = 2_000_000

/** 与后端 `src/extract.py` 的 LANGUAGE_BY_EXT 对齐。 */
const OK_EXTS = new Set([
  '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx',
  '.py', '.pyw', '.pyi', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.php', '.php3', '.php5', '.phtml',
])

let seq = 0
/** 行的身份。**不要用文件名** —— 用户完全可以选两个都叫 test.c 的文件。 */
const uid = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `f${++seq}`

/**
 * 打开页面就载入静态报告，省掉一次点击。
 *
 * 两种写法都行：
 *   `?r=xxx.json` —— 指定看哪一份（见 `api.ts` 的 `resolveStaticReport`）
 *   `?sample=1`   —— 看默认那份
 *
 * 用途：直接给个链接就能演示，以及**后端没起时**确认界面本身是好的。
 */
const AUTO_SAMPLE = (() => {
  if (typeof window === 'undefined') return false
  const q = new URLSearchParams(window.location.search)
  return q.get('sample') === '1' || q.has('r')
})()

export default function App() {
  const [health, setHealth] = useState<HealthInfo | null>(null)
  const [healthErr, setHealthErr] = useState<string | null>(null)

  const [pending, setPending] = useState<PendingFile[]>([])
  const [receipt, setReceipt] = useState<UploadReceipt[] | null>(null)
  const [report, setReport] = useState<ScanReport | null>(null)
  const [isSample, setIsSample] = useState(false)

  const [scanning, setScanning] = useState(false)
  const [scanErr, setScanErr] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [selectedFn, setSelectedFn] = useState<FunctionInfo | null>(null)

  const detailRef = useRef<HTMLDivElement>(null)

  /* ------------------------------------------------- 轮询模型状态 */
  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout>

    const tick = async () => {
      try {
        const h = await loadHealth()
        if (!alive) return
        setHealth(h)
        setHealthErr(null)
        // 还没就绪就继续等；就绪/失败之后不再打扰后端
        if (h.status === 'loading') timer = setTimeout(tick, 2000)
      } catch (e) {
        if (!alive) return
        setHealth(null)
        setHealthErr((e as Error).message)
        timer = setTimeout(tick, 5000)
      }
    }
    tick()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [])

  /* ------------------------------------------------- 视图数据（唯一一次 join） */
  // 示例模式下，报告里的文件先铺在下面；用户自己添加的文件追加在后面。
  // 两者共存，所以"看示例的同时加自己的文件"也不会把先看到的东西挤掉。
  const rows: FileRow[] = useMemo(() => {
    const sampleRows = isSample && report ? rowsFromReport(report) : []
    return [...sampleRows, ...buildRows(pending, receipt, report)]
  }, [isSample, report, pending, receipt])

  const selectedRow = useMemo(
    () => rows.find((r) => r.client_id === selectedId) ?? null,
    [rows, selectedId],
  )

  /* ------------------------------------------------- 操作 */
  const onAddFiles = useCallback(async (files: FileList) => {
    const accepted: PendingFile[] = []
    const rejected: string[] = []

    for (const f of Array.from(files)) {
      const dot = f.name.lastIndexOf('.')
      const ext = dot >= 0 ? f.name.slice(dot).toLowerCase() : ''
      // 在**选择时**就挡掉，别让用户等一次请求才知道不行
      if (!OK_EXTS.has(ext)) {
        rejected.push(`${f.name}（不认识 .${ext.replace('.', '') || '无扩展名'}）`)
        continue
      }
      if (f.size > MAX_FILE_BYTES) {
        rejected.push(`${f.name}（${(f.size / 1048576).toFixed(1)} MB，超 2 MB 上限）`)
        continue
      }
      // 读**原始字节**，不要 file.text() —— 见 api.ts 里 runScan 的注释
      accepted.push({ client_id: uid(), name: f.name, bytes: await readFileBytes(f) })
    }

    setNotice(rejected.length ? `已跳过 ${rejected.join('、')}` : null)
    if (accepted.length) {
      setPending((p) => [...p, ...accepted])
      setScanErr(null)
      // ⚠️ 这里**刻意不清空** report / receipt。
      // 已经扫出来的结果要留在屏幕上 —— 用户加个文件只是想再扫一轮，
      // 不是想把刚才的结果丢掉。新加的文件在侧栏显示为「待检测」，
      // 等点了「开始检测」才和其它文件一起送进模型。
    }
  }, [])

  const onRemove = useCallback((id: string) => {
    setPending((p) => p.filter((x) => x.client_id !== id))
    setReceipt((r) => (r ? r.filter((u) => u.client_id !== id) : r))
    setSelectedId((s) => (s === id ? null : s))
  }, [])

  const onClear = useCallback(() => {
    setPending([])
    setReceipt(null)
    setReport(null)
    setIsSample(false)
    setScanErr(null)
    setNotice(null)
    setSelectedId(null)
    setSelectedFn(null)
  }, [])

  const onScan = useCallback(async () => {
    setScanning(true)
    setScanErr(null)
    setIsSample(false)
    try {
      const res = await runScan(pending)
      setReport(res.report)
      setReceipt(res.uploads)
    } catch (e) {
      const err = e as ApiError
      setScanErr(
        err.status === 409
          ? `${err.message}`
          : err.status === 503
            ? `模型还没准备好：${err.message}`
            : err.message,
      )
    } finally {
      setScanning(false)
    }
  }, [pending])

  const onLoadSample = useCallback(async () => {
    setScanErr(null)
    try {
      const r = await loadSampleReport()
      setReport(r)
      setReceipt(null)
      setIsSample(true)
      setSelectedId(null)
      setSelectedFn(null)
    } catch (e) {
      setScanErr((e as Error).message)
    }
  }, [])

  // ?sample=1：打开就载入示例报告
  const sampleOnce = useRef(false)
  useEffect(() => {
    if (AUTO_SAMPLE && !sampleOnce.current) {
      sampleOnce.current = true
      void onLoadSample()
    }
  }, [onLoadSample])

  const selectFile = useCallback((id: string) => {
    setSelectedId(id)
    setSelectedFn(null)
  }, [])

  /**
   * 选中文件后把详情滚进视野。
   *
   * 详情在图表**下面**，不滚的话点侧栏一整个像没反应（只是左边的边框动了），
   * 用户根本不知道函数清单已经出来了。所以只要有得看就滚过去。
   */
  useEffect(() => {
    if (!selectedId) return
    const row = rows.find((r) => r.client_id === selectedId)
    if (!row?.file?.functions.length) return
    detailRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [selectedId, rows])

  /* ------------------------------------------------- 「开始检测」能不能点 */
  const scanHint = useMemo(() => {
    if (healthErr !== null) return '后端没起来，先在终端跑 scripts/serve.py'
    if (!health) return '正在连接后端…'
    if (health.status === 'loading') return '模型还在加载，稍等一下'
    if (health.status === 'error') return '模型加载失败，看后端终端的日志'
    if (pending.length === 0) return '先添加文件'
    return null
  }, [health, healthErr, pending.length])

  const detected = report?.checkpoint != null

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header health={health} healthErr={healthErr} />

      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        <Sidebar
          rows={rows}
          selectedId={selectedId}
          onSelect={selectFile}
          onAddFiles={onAddFiles}
          onRemove={onRemove}
          onScan={onScan}
          onClear={onClear}
          scanning={scanning}
          scanHint={scanHint}
        />

        <main style={{ flex: 1, minWidth: 0, overflowY: 'auto', background: 'var(--paper)' }}>
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
            {notice && (
              <Alert type="warning" showIcon closable message={notice} onClose={() => setNotice(null)} />
            )}
            {scanErr && (
              <Alert
                type="error"
                showIcon
                closable
                message="检测失败"
                description={<span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{scanErr}</span>}
                onClose={() => setScanErr(null)}
              />
            )}
            {isSample && (
              <Alert
                type="info"
                showIcon
                message="这是随包发布的示例报告"
                description={`扫描自 ${shortPath(report?.root ?? '', 2)}，不是你自己添加的文件。点左栏「添加文件」开始真正的检测。`}
              />
            )}

            {!report ? (
              <EmptyState
                scanning={scanning}
                canScan={!scanHint}
                onLoadSample={onLoadSample}
                hasPending={pending.length > 0}
              />
            ) : (
              <>
                <Overview report={report} rows={rows} />

                {detected && (
                  <ProbHistogram files={report.files} threshold={report.threshold} />
                )}

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(430px, 1fr))',
                    gap: 14,
                  }}
                >
                  <FileRiskRanking
                    rows={rows}
                    selectedId={selectedId ?? undefined}
                    onSelect={selectFile}
                  />
                  <CweDistribution report={report} />
                </div>

                {detected && (
                  <RiskHeatmap
                    rows={rows}
                    threshold={report.threshold}
                    selectedId={selectedId ?? undefined}
                    onSelect={selectFile}
                  />
                )}

                {/* 下钻：选中的文件 → 函数清单 → 源码与判定 */}
                <div ref={detailRef}>
                  {selectedRow?.file && selectedRow.file.functions.length > 0 && (
                    <section className="panel" style={{ overflow: 'hidden' }}>
                      <FunctionList
                        file={selectedRow.file}
                        fileLabel={selectedRow.displayName}
                        threshold={report.threshold}
                        selected={selectedFn}
                        onSelect={setSelectedFn}
                      />
                      {selectedFn && (
                        <div style={{ padding: 16, borderTop: '1px solid var(--rule)' }}>
                          <FunctionDetail
                            fn={selectedFn}
                            // 用用户认得的文件名。报告里的 `0000/curl.c`
                            // 是后端为了防重名编的内部路径，对看的人没有意义。
                            file={selectedRow.displayName}
                            language={selectedRow.file.language ?? selectedFn.language}
                            threshold={report.threshold}
                          />
                        </div>
                      )}
                    </section>
                  )}
                </div>
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ 空态 */

function EmptyState({
  scanning,
  canScan,
  hasPending,
  onLoadSample,
}: {
  scanning: boolean
  canScan: boolean
  hasPending: boolean
  onLoadSample: () => void
}) {
  return (
    <div
      className="panel"
      style={{
        padding: '64px 24px',
        textAlign: 'center',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 14,
      }}
    >
      <svg width="44" height="44" viewBox="0 0 26 26" aria-hidden>
        <rect x="1.5" y="1.5" width="23" height="23" rx="3" fill="none"
              stroke="var(--rule)" strokeWidth="2" />
        <path d="M7 13.5 L11.5 18 L19 8" fill="none" stroke="var(--rule)"
              strokeWidth="2.6" strokeLinecap="square" />
      </svg>

      <div style={{ fontSize: 15, fontWeight: 500 }}>
        {scanning ? '正在检测…' : hasPending ? '文件准备好了，可以开始检测' : '还没有要检测的文件'}
      </div>

      <div style={{ fontSize: 12.5, color: 'var(--ink-3)', lineHeight: 1.8, maxWidth: 440 }}>
        {scanning ? (
          '模型正在逐个函数推理，稍等片刻'
        ) : hasPending ? (
          <>
            点左栏的 <b style={{ color: 'var(--ink-2)' }}>开始检测</b>，
            后端会真跑 CodeBERT 模型逐个函数判断
          </>
        ) : (
          <>
            点左栏的 <b style={{ color: 'var(--ink-2)' }}>添加文件</b> 选几个 C 源文件，
            再点 <b style={{ color: 'var(--ink-2)' }}>开始检测</b>
            <br />
            检测和分类都是真跑本地模型，不是演示数据
          </>
        )}
      </div>

      {!hasPending && !scanning && (
        <button className="linkish" style={{ fontSize: 12, marginTop: 4 }} onClick={onLoadSample}>
          或者，先看看随包发布的示例报告 →
        </button>
      )}

      {!canScan && !hasPending && (
        <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>
          （示例报告不需要后端，任何时候都能看）
        </div>
      )}
    </div>
  )
}
