/**
 * 扫描报告的类型定义。
 *
 * 对应后端 `scripts/scan_project.py` 的 `build_report()`，权威说明见
 * `docs/08_全流程与接口规范.md` 第 3 节。
 *
 * ⚠️ 几个必须理解的约定（不遵守会导致换个扫描参数就白屏）
 * ========================================================
 *
 * **1. 可选字段是「键不存在」，不是 `null`**
 *
 * `build_report()` 刻意不写 `null` —— 因为 `"verdict": null` 会被读成
 * "模型判定为安全"，`"cwe": null` 会被读成"没有类别"。而"没跑过推理"
 * 和"判定为空"是两码事。
 *
 * 所以判断写法是 `'cwe' in fn` 或 `fn.cwe !== undefined`，
 * **不要**写 `fn.cwe !== null`。
 *
 * 各字段的出现条件：
 *
 * | 字段                        | 什么时候有                        |
 * |-----------------------------|-----------------------------------|
 * | `verdict`/`confidence`/`prob_vulnerable` | 传了 `--checkpoint`（跑了检测） |
 * | `cwe`/`cwe_topk`            | 判定为 vulnerable **且**传了 `--classifier` |
 * | `code`                      | 没传 `--no-code`                  |
 *
 * **2. 只有 `parent_name` 真的可能是 `null`**
 *
 * 顶层函数的 `parent_name` 就是 `null`，这是有意义的取值，不是"缺字段"。
 *
 * **3. `confidence` 的含义随判定结果变化**
 *
 * - 判定为 `vulnerable` 时，它**恒等于** `prob_vulnerable`
 * - 判定为 `safe` 时，它是 `p(safe)`，不是漏洞概率
 *
 * 所以**排序和展示一律用 `prob_vulnerable`**，语义才一致。
 */

/** 检测任务的判定结果。 */
export type Verdict = 'safe' | 'vulnerable'

/** `cwe_topk` 里的一项：一个候选类别和它的概率。 */
export interface TopKItem {
  /** CWE 编号（如 `"CWE-119"`），也可能是 `"OTHER"` —— 别当正则解析 */
  cwe: string
  prob: number
}

/** 一个被抽取出来的函数，以及它在各阶段得到的结果。 */
export interface FunctionInfo {
  // ---- 抽取阶段（一定有）----
  name: string
  /** 起始行号，从 1 开始 —— 前端做代码行号直接用这个，不用自己数 */
  start_line: number
  end_line: number
  start_byte: number
  end_byte: number
  /** tree-sitter 节点类型，常见 `function_definition`、`decorated_definition` */
  node_type: string
  language: string
  /** 嵌套深度：0 = 顶层。类方法算 0（类不算函数） */
  depth: number
  /** 外层函数名；**顶层函数是 `null`**（这是唯一真正会用 null 的字段） */
  parent_name: string | null

  // ---- 检测阶段（传了 --checkpoint 才有）----
  /** 函数源码。用了 `--no-code` 就**没有这个键**。单函数最长约 20 KB */
  code?: string
  verdict?: Verdict
  confidence?: number
  prob_vulnerable?: number

  // ---- 分类阶段（vulnerable 且传了 --classifier 才有）----
  /** 预测的 CWE 类别。可能是 `"OTHER"` */
  cwe?: string
  /** Top-N 候选，长度是 `min(5, 类别数)` —— 别硬编码 5 */
  cwe_topk?: TopKItem[]
}

/** 一个源文件的抽取结果与统计。 */
export interface FileResult {
  /** 相对路径，POSIX 风格（用 `/` 不用 `\`） */
  path: string
  language: string | null
  /** 语法树有没有 ERROR 节点 */
  parse_ok: boolean
  num_bytes: number
  function_count: number
  /** 这个文件里判定为有漏洞的函数数 —— 文件级的核心指标 */
  suspicious_count: number
  /** 因语法错误被丢弃的函数数 */
  functions_discarded: number
  functions: FunctionInfo[]
}

/** 被跳过的文件。扫大项目时可能非空。 */
export interface SkippedItem {
  path: string
  /** 形如 `"PermissionError: ..."` / `"too_large"` / `"binary"` */
  reason: string
}

/** 项目级统计。 */
export interface Summary {
  files_scanned: number
  files_skipped: number
  functions_total: number
  /** 整个项目里判定为有漏洞的函数数 */
  functions_suspicious: number
  /** 成功拿到 CWE 的函数数（= 命中函数里跑了分类的那些） */
  functions_classified: number
  /** ⚠️ 是「语言 → **函数数**」，不是文件数 */
  languages: Record<string, number>
}

/** 一次扫描的完整报告。 */
export interface ScanReport {
  /** 当前恒为 1。约定：新增可选字段不递增版本，只有破坏性变更才加 */
  schema_version: number
  tool: string
  /** 本地时区 ISO 8601 */
  generated_at: string
  /** 扫描根目录的**绝对路径**。可能是别的机器的路径，只展示不解析 */
  root: string
  /** 检测模型路径；没跑推理时为 `null` */
  checkpoint: string | null
  /**
   * 实际生效的判定阈值；没跑推理时为 `null`。
   * ⚠️ 是未取整的原始浮点数（实测见过 `0.10999999999999997`），展示前要格式化
   */
  threshold: number | null
  /** 分类模型路径；没跑分类时为 `null` */
  classifier_checkpoint: string | null
  summary: Summary
  skipped: SkippedItem[]
  files: FileResult[]
}
