/**
 * CWE 编号 → 中文简称。
 *
 * 为什么需要这张表：**项目里本来没有任何 CWE→中文名的映射**。
 * 各 run 的 `best/label_map.json` 里只有「序号 ↔ CWE 编号」，
 * 英文全称只散落在数据 JSONL 的 `cwe_name` 字段里。但界面上
 * 「CWE-119 缓冲区溢出」比光秃秃一个「CWE-119」可读得多 —— 这正是这个页面要解决的问题。
 *
 * 表里覆盖的是 `merged_top27` 分类模型的 **28 个类别**
 * （27 个 CWE + `OTHER`，来自 `scripts/relabel_classes.py --top-k 27`）。
 * 编号与 `outputs/merged_top27_codebert_e20/best/label_map.json` 的 `id2name` 一一对应。
 *
 * ⚠️ 换成别的分类模型（比如 41 类的 `cvefixes_classification`）时，
 * 表里没有的编号**原样显示编号**，绝不猜 —— 猜错一个 CWE 的含义，
 * 比不显示中文名糟糕得多。
 */

/** 28 个类别的中文简称。 */
export const CWE_NAMES: Readonly<Record<string, string>> = {
  'CWE-119': '缓冲区溢出',
  'CWE-79': '跨站脚本',
  'CWE-20': '输入验证不当',
  'CWE-125': '越界读取',
  'CWE-399': '资源管理错误',
  'CWE-200': '信息泄露',
  'CWE-264': '权限许可与访问控制',
  'CWE-416': '释放后使用',
  'CWE-787': '越界写入',
  'CWE-190': '整数溢出',
  'CWE-476': '空指针解引用',
  'CWE-189': '数值计算错误',
  'CWE-362': '竞争条件',
  'CWE-89': 'SQL 注入',
  'CWE-22': '路径遍历',
  'CWE-284': '访问控制不当',
  'CWE-352': '跨站请求伪造',
  'CWE-78': 'OS 命令注入',
  'CWE-400': '资源耗尽',
  'CWE-94': '代码注入',
  'CWE-287': '身份认证不当',
  'CWE-254': '安全特性缺失',
  'CWE-918': '服务端请求伪造',
  'CWE-415': '双重释放',
  'CWE-863': '权限校验不当',
  'CWE-310': '加密问题',
  'CWE-59': '链接跟随',
  OTHER: '其他（长尾杂项）',
}

/**
 * 中文简称；**查不到时返回 `null`**。
 *
 * 调用方据此回退到只显示编号（见 `CweDistribution` 里对 `known` 的判断）——
 * 表里没有的编号不该硬编一个中文名出来。
 */
export function cweName(cwe: string | undefined): string | null {
  if (!cwe) return null
  return CWE_NAMES[cwe] ?? null
}
