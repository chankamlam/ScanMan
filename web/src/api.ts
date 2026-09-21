/**
 * 数据层：把「报告从哪来」这件事和界面解耦。
 *
 * 两种数据来源，**返回的数据结构完全一样**，组件不用关心用的是哪种：
 *
 *   static（默认）—— 读 `public/sample_report.json`，一个提前跑好的真实报告。
 *                    不需要后端、不需要模型，打开页面就有内容。
 *   api            —— 调本机 FastAPI（`scripts/serve.py`），支持真实扫描。
 *
 * 切换方式：环境变量 `VITE_DATA_SOURCE=api npm run dev`，
 * 或者运行时的界面上切换（见 App.tsx）。
 */

import type { ScanReport } from './types'

/** 后端 `/api/health` 的返回。 */
export interface HealthInfo {
  models_loaded: boolean
  device: string
  gpu: string
  detector: string | null
  classifier: string | null
  num_labels: number | null
  error?: string
}

/** 扫描任务的状态。 */
export interface ScanStatus {
  status: 'pending' | 'running' | 'done' | 'failed'
  /** 只在 `running` 时有意义 */
  progress?: { done: number; total: number }
  /** 只在 `done` 时存在 */
  summary?: ScanReport['summary']
  /** 只在 `failed` 时存在 */
  error?: string
}

/** 静态报告的路径。`public/` 下的文件会被原样发布到根路径。 */
const DEFAULT_STATIC_REPORT = '/sample_report.json'

/**
 * 解析实际要读哪份静态报告。
 *
 * 默认读 `public/sample_report.json`；带 `?r=xxx.json` 时改读 `public/xxx.json`。
 *
 * 为什么留这个口子：报告里**有些字段是"有则有、无则无"**（`verdict` / `cwe` /
 * `code` 都可能整个不存在），换一种扫描参数就会变。要验证界面在字段缺失时
 * 不白屏，就得能方便地换一份报告来看 —— 否则只能改代码重新构建。
 *
 * 用法：`http://localhost:5173/?r=_t_extractonly.json`
 */
function resolveStaticReport(): string {
  if (typeof window === 'undefined') return DEFAULT_STATIC_REPORT
  const r = new URLSearchParams(window.location.search).get('r')
  if (!r) return DEFAULT_STATIC_REPORT
  // 只允许取 public/ 下的文件名，不接受路径分隔符或协议前缀
  if (!/^[A-Za-z0-9_.-]+\.json$/.test(r)) {
    console.warn(`忽略非法的 ?r= 参数：${r}`)
    return DEFAULT_STATIC_REPORT
  }
  return `/${r}`
}

/**
 * 读一份报告。
 *
 * @param taskId 指定时从后端取这个任务的报告；不传则按当前模式取。
 *               （阶段 1 只会走「不传」这条路）
 */
export async function loadReport(taskId?: string): Promise<ScanReport> {
  if (taskId) {
    return getJson<ScanReport>(`/api/scan/${taskId}/report`)
  }
  return getJson<ScanReport>(resolveStaticReport())
}

/** 查后端状态。演示前用它确认模型加载好了没。 */
export async function loadHealth(): Promise<HealthInfo> {
  return getJson<HealthInfo>('/api/health')
}

/** 提交一个扫描任务，立即返回（不阻塞）。 */
export async function startScan(
  path: string,
  includeCode = true,
): Promise<{ task_id: string; status: string }> {
  const resp = await fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, include_code: includeCode }),
  })
  return unwrap<{ task_id: string; status: string }>(resp)
}

/** 查任务状态。前端按固定间隔轮询这个接口。 */
export async function pollScan(taskId: string): Promise<ScanStatus> {
  return getJson<ScanStatus>(`/api/scan/${taskId}`)
}

// ---------------------------------------------------------------- 内部工具

/**
 * 统一的 GET。
 *
 * 把 HTTP 错误和「返回的不是 JSON」都转成带上下文的异常 ——
 * 否则演示现场看到的是浏览器控制台里一句没头没尾的报错。
 */
async function getJson<T>(url: string): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(url)
  } catch (e) {
    throw new Error(`连不上 ${url}：${(e as Error).message}`)
  }
  return unwrap<T>(resp)
}

async function unwrap<T>(resp: Response): Promise<T> {
  const text = await resp.text()
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}：${text.slice(0, 200)}`)
  }
  try {
    return JSON.parse(text) as T
  } catch {
    // 典型场景：静态报告还没生成，服务器返回了 index.html
    throw new Error(
      `返回的不是 JSON（前 120 字符）：${text.slice(0, 120)}`,
    )
  }
}
