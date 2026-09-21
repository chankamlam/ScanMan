/**
 * 数据层：这个页面唯一的对外出口。
 *
 * 后端是 `scripts/serve.py`（Flask，监听 127.0.0.1:8000）。
 * 开发时前端发 `/api/*`，由 `vite.config.ts` 的 proxy 转发过去，
 * 所以这里**一律写相对路径**，不用区分开发/生产。
 *
 * 两条数据来源：
 *
 *   真实检测 —— `runScan()`，把用户选的文件 POST 上去，后端真跑模型。
 *   示例报告 —— `loadSampleReport()`，读 `public/sample_report.json`。
 *               模型没就绪（或后端没起）时，界面不至于是一片空白。
 */

import type { ScanReport } from './types'

/* ------------------------------------------------------------------ 类型 */

/** 后端 `/api/health` 的返回。 */
export interface HealthInfo {
  /** `ready` 才代表「点了就快」—— 权重加载完还要预热 CUDA，见 serve.py */
  status: 'loading' | 'ready' | 'error'
  models_loaded: boolean
  device: string | null
  gpu: string | null
  detector: string | null
  classifier: string | null
  /** 检测模型的判定阈值；未就绪时为 null */
  threshold: number | null
  /** 分类模型的类别数（本项目是 28） */
  num_labels: number | null
  /** 仅 `status === 'error'` 时有值 */
  error: string | null
}

/** 一个待上传的文件。`client_id` 由前端生成，是这一行**唯一**的身份。 */
export interface PendingFile {
  /** 前端生成。**不要用文件名当身份** —— 用户可能选两个都叫 `test.c` 的文件 */
  client_id: string
  name: string
  /** 原始字节。**必须是字节**，不能先读成字符串，理由见 `runScan` 的注释 */
  bytes: ArrayBuffer
}

/** 后端对每个上传文件的回执。 */
export interface UploadReceipt {
  client_id: string
  name: string
  /** 报告里的相对路径，形如 `0000/test.c`。这是回执和 `report.files` 之间唯一的桥 */
  path: string
  /**
   * `skipped` 表示这个文件没能抽取出函数（二进制、编码怪、体积超限…）。
   * 注意它**不在** `report.files` 里 —— 那边是带洞的子序列。
   */
  status: 'scanned' | 'skipped'
  reason?: string
}

export interface ScanResponse {
  report: ScanReport
  uploads: UploadReceipt[]
}

/** 带 HTTP 状态码的错误，界面据此区分「参数错」/「已有扫描」/「模型没就绪」。 */
export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/* --------------------------------------------------------------- 接口调用 */

/** 查后端与模型状态。界面轮询它来显示「模型加载中／就绪／失败」。 */
export async function loadHealth(): Promise<HealthInfo> {
  return requestJson<HealthInfo>('/api/health')
}

/**
 * 把文件交给后端真跑模型。
 *
 * ⚠️ **必须传原始字节，不能先用 `FileReader.readAsText()`。**
 * 后端的 `src/extract.py` 是**以字节为真相源**解析的（这样才处理得了
 * GBK 等非 UTF-8 文件）。若在前端按 UTF-8 解一次、再编码回 UTF-8，
 * 中文字符会变成替换字符，**字节偏移随之改变 —— 于是 `start_line` 全错**，
 * 界面上源码的行号会指向错误的位置。所以这里走 base64 传字节。
 */
export async function runScan(files: PendingFile[]): Promise<ScanResponse> {
  return requestJson<ScanResponse>('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      files: files.map((f) => ({
        client_id: f.client_id,
        name: f.name,
        content_b64: toBase64(f.bytes),
      })),
    }),
  })
}

/** 默认的静态报告。`public/` 下的文件会被原样发布到根路径。 */
const DEFAULT_REPORT = '/sample_report.json'

/**
 * 解析要读哪份静态报告 —— `?r=xxx.json` 指定，缺省读 `sample_report.json`。
 *
 * 为什么留这个口子：报告里**有些字段是"有则有、无则无"**
 * （`verdict` / `cwe` / `code` 都可能整个不存在），换一组扫描参数就会变。
 * `public/` 里就放着三份：完整级联、仅检测、仅抽取 ——
 * 后两份正是用来验证「没跑过检测」不会被误显示成「判定为安全」的
 * （见 `rows.ts` 里那六种文件状态）。没有这个参数就只能改代码重新构建。
 *
 * 用法：`http://localhost:5173/?r=sample_report_extract_only.json`
 */
function resolveStaticReport(): string {
  if (typeof window === 'undefined') return DEFAULT_REPORT
  const r = new URLSearchParams(window.location.search).get('r')
  if (!r) return DEFAULT_REPORT
  // 只允许取 public/ 下的文件名，不接受路径分隔符或协议前缀
  if (!/^[A-Za-z0-9_.-]+\.json$/.test(r)) {
    console.warn(`忽略非法的 ?r= 参数：${r}`)
    return DEFAULT_REPORT
  }
  return `/${r}`
}

/** 读一份静态示例报告。模型没就绪（或后端没起）时用它兜底演示。 */
export async function loadSampleReport(): Promise<ScanReport> {
  return requestJson<ScanReport>(resolveStaticReport())
}

/* --------------------------------------------------------------- 内部工具 */

/**
 * `ArrayBuffer` → base64。
 *
 * 分块处理：`String.fromCharCode(...bytes)` 的展开参数有上限，
 * 一次性丢几 MB 进去会 `RangeError: Maximum call stack size exceeded`。
 */
export function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  const CHUNK = 0x8000
  let bin = ''
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(bin)
}

/** 把 File 读成原始字节。**不要**换成 `file.text()`，理由见 `runScan`。 */
export async function readFileBytes(file: File): Promise<ArrayBuffer> {
  return file.arrayBuffer()
}

/**
 * 统一的请求封装。
 *
 * 把三类失败都转成**带上下文的** `ApiError` —— 否则演示现场看到的
 * 只是浏览器控制台里一句没头没尾的报错：
 *
 *   - 连不上（后端没起）
 *   - HTTP 非 2xx（后端返回了 `{error}`，把它的消息带出来）
 *   - 返回的不是 JSON（**最常见**：后端没起时 vite proxy 回退成 HTML 错误页）
 */
async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(url, init)
  } catch (e) {
    throw new ApiError(
      `连不上后端（${url}）。确认 scripts/serve.py 起着吗？ —— ${(e as Error).message}`,
      0,
    )
  }

  const text = await resp.text()

  if (!resp.ok) {
    // 后端所有错误路径都返回 {error: "..."}，优先用它的消息
    let msg = ''
    try {
      const j = JSON.parse(text) as { error?: string; detail?: string }
      if (j.error) msg = j.detail ? `${j.error}（${j.detail}）` : j.error
    } catch {
      /* 不是 JSON 就退回原文 */
    }
    if (!msg) msg = text.trim().slice(0, 200)
    if (!msg) {
      // ⚠️ 空响应体不能留成空字符串 —— 空串是 falsy，
      // 调用方一句 `if (errMsg)` 就会把"出错了"误判成"没事"，
      // 界面于是显示成"正在连接…"而不是"连不上"。
      //
      // 而空响应体最常见的原因恰恰是**后端没起**：vite 的 proxy 转发失败时
      // 返回的就是一个 500 加空 body。这时候只说 "HTTP 500" 帮不上忙。
      msg =
        resp.status === 500 || resp.status === 502 || resp.status === 504
          ? `HTTP ${resp.status}（响应体为空，多半是 scripts/serve.py 没起来）`
          : `HTTP ${resp.status} ${resp.statusText || ''}`.trim()
    }
    throw new ApiError(msg, resp.status)
  }

  try {
    return JSON.parse(text) as T
  } catch {
    throw new ApiError(
      `后端返回的不是 JSON（前 120 字符）：${text.slice(0, 120)}`,
      resp.status,
    )
  }
}
