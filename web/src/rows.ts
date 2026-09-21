/**
 * 把「用户添加的文件」和「后端返回的报告」拼成一份**统一的视图数据**。
 *
 * 为什么需要这一步：`scan_project.py` 在异常和 `res.error` 两条路径上都是
 * `continue`，**跳过的文件根本不进 `file_results`** —— 所以
 * `report.files` 是上传集合的**带洞子序列**。
 *
 * 于是两种"想当然"的对齐方式都是错的：
 *
 *   - **按下标对齐** —— 一旦有文件被跳过，后面全部错位；
 *   - **按文件名对齐** —— 用户完全可以选两个都叫 `test.c` 的文件。
 *
 * 正确的做法是让身份**显式传递**：前端给每行生成 `client_id`，
 * 后端在回执里原样带回，再用 `uploads[].path` 这唯一的桥接到 `report.files`。
 * 全程只 join 一次，之后所有视图都读同一份 `FileRow[]`。
 */

import type { FileResult, FunctionInfo, ScanReport } from './types'
import type { UploadReceipt } from './api'

/**
 * 一个文件在界面上的状态。
 *
 * ⚠️ **有五种，不是两种。** 把 `suspicious_count > 0 ? 红 : 绿` 当判据的话，
 * 「没跑过检测」会被涂成绿色的"安全" —— 这正是 `types.ts` 开头警告的
 * 「把'没跑过'读成'判定为空'」。`public/sample_report_extract_only.json`
 * 就是这样一份报告：一个 `verdict` 都没有。
 */
export type FileState =
  /** 刚添加，这一轮还没扫到它（扫完后再添加的文件就是这状态） */
  | 'pending'
  /** 抽取失败（二进制、编码怪、体积超限…）—— 根本没进报告 */
  | 'failed'
  /** 抽出来了，但一个函数都没有（C 项目里 `.h` 常常只有声明） */
  | 'empty'
  /** 有函数，但这份报告没跑检测模型 */
  | 'undetected'
  /** 检测过了，一个都没命中 */
  | 'clean'
  /** 检测过了，有命中 */
  | 'hit'

export interface FileRow {
  /** 前端生成的行身份。**React key 用它，不要用文件名** */
  client_id: string
  /** 展示用的文件名（用户选的那个），不含报告里的 `0000/` 前缀 */
  displayName: string
  /** 报告里的相对路径；抽取失败时为 undefined */
  path?: string
  state: FileState
  /** 抽取失败的原因，直接抄后端的 `skipped[].reason` */
  reason?: string
  /** 抽取结果；`state === 'failed'` 时不存在 */
  file?: FileResult
}

/** 这份报告跑过检测吗（只要有一个函数带 `prob_vulnerable` 就算）。 */
export function detected(report: ScanReport | null): boolean {
  if (!report) return false
  return report.files.some((fr) =>
    fr.functions.some((f) => 'prob_vulnerable' in f),
  )
}

/**
 * 一个文件的状态。
 *
 * 注意「没有回执」和「有回执但没进报告」是两回事：
 * 前者是**还没扫到它**（扫完之后又添了新文件），后者才是**抽取失败**。
 * 混为一谈的话，新添加的文件会立刻显示成红色的"抽取失败"。
 */
export function stateOf(
  file: FileResult | undefined,
  receipt: UploadReceipt | undefined,
  reported: boolean,
): FileState {
  if (!receipt) return 'pending'
  if (!file) return 'failed'
  if (file.function_count === 0) return 'empty'
  if (!reported) return 'undetected'
  return file.suspicious_count > 0 ? 'hit' : 'clean'
}

/**
 * 生成视图数据。这是全页唯一一次 join。
 *
 * @param pending 用户添加的文件（`client_id` / `name`）
 * @param receipt 后端的回执；还没扫过时传 undefined
 * @param report  报告；还没扫过时传 null
 */
export function buildRows(
  pending: { client_id: string; name: string }[],
  receipt: UploadReceipt[] | null,
  report: ScanReport | null,
): FileRow[] {
  const byClient = new Map((receipt ?? []).map((u) => [u.client_id, u]))
  const byPath = new Map((report?.files ?? []).map((f) => [f.path, f]))
  const reported = detected(report)

  return pending.map((p) => {
    const u = byClient.get(p.client_id)
    const file = u?.path ? byPath.get(u.path) : undefined
    return {
      client_id: p.client_id,
      displayName: p.name,
      path: file?.path,
      state: stateOf(file, u, reported),
      reason: u?.reason,
      file,
    }
  })
}

/**
 * 直接从一份报告生成视图数据 —— 给"载入示例报告"用。
 *
 * 示例报告没有上传回执，所以 `client_id` 直接用报告里的 path 顶替
 * （它在报告内部本来就是唯一的）。
 */
export function rowsFromReport(report: ScanReport): FileRow[] {
  const reported = detected(report)
  return report.files.map((fr) => ({
    client_id: fr.path,
    displayName: fr.path,
    path: fr.path,
    state: stateOf(fr, { client_id: fr.path, name: fr.path, path: fr.path, status: 'scanned' }, reported),
    file: fr,
  }))
}

/* ------------------------------------------------------------ 状态 → 外观 */

export interface StateBadge {
  label: string
  /** 文字色 token */
  color: string
  /** 底色 token */
  bg: string
}

export function stateBadge(row: FileRow): StateBadge | null {
  const file = row.file
  switch (row.state) {
    case 'pending':
      return { label: '待检测', color: 'var(--signal)', bg: '#eef2fd' }
    case 'failed':
      return { label: '抽取失败', color: 'var(--warn)', bg: '#fdf3e3' }
    case 'empty':
      return { label: '无函数', color: 'var(--ink-3)', bg: 'var(--surface-2)' }
    case 'undetected':
      return { label: '未检测', color: 'var(--ink-3)', bg: 'var(--surface-2)' }
    case 'clean':
      return { label: '未命中', color: 'var(--ok)', bg: 'var(--ok-bg)' }
    case 'hit':
      return {
        label: `命中 ${file!.suspicious_count}/${file!.function_count}`,
        color: 'var(--flag)',
        bg: 'var(--flag-bg)',
      }
  }
}

/* ------------------------------------------------------------ 函数排序 */

/**
 * 一个文件里的函数，按需要排序。
 *
 * 默认按**漏洞概率降序** —— 看报告的人最想知道"最该看哪个"。
 * 没有概率时退回按行号（保持源码顺序，那是源码唯一有意义的顺序）。
 */
export function sortFunctions(fns: FunctionInfo[], byProb = true): FunctionInfo[] {
  const copy = [...fns]
  if (!byProb) return copy.sort((a, b) => a.start_line - b.start_line)
  return copy.sort((a, b) => {
    const av = a.prob_vulnerable
    const bv = b.prob_vulnerable
    if (av === undefined && bv === undefined) return a.start_line - b.start_line
    if (av === undefined) return 1
    if (bv === undefined) return -1
    if (bv !== av) return bv - av
    return a.start_line - b.start_line
  })
}
