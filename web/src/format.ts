/**
 * 展示层的小工具。
 *
 * 存在的理由：后端写进报告的是**原始数值**，直接渲染会很难看。
 * 实测见过 `threshold: 0.10999999999999997` 和 16 位有效数字的
 * `confidence` —— 这些是浮点运算的正常产物，不该原样丢给用户。
 */

/** 把 0~1 的概率格式化成百分比。`0.6236` → `"62.4%"` */
export function pct(x: number | undefined, digits = 1): string {
  if (x === undefined || x === null || Number.isNaN(x)) return '—'
  return `${(x * 100).toFixed(digits)}%`
}

/** 固定小数位。用于阈值这类需要精确显示的数字。`0.10999999999999997` → `"0.1100"` */
export function fixed(x: number | undefined, digits = 4): string {
  if (x === undefined || x === null || Number.isNaN(x)) return '—'
  return x.toFixed(digits)
}

/** 大数字加千分位。`429308` → `"429,308"` */
export function num(n: number | undefined): string {
  if (n === undefined || n === null) return '—'
  return n.toLocaleString('en-US')
}

/** 字节数转可读单位。 */
export function bytes(n: number | undefined): string {
  if (n === undefined || n === null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

/**
 * 把后端可能很长的绝对路径缩短，只保留最后两段。
 *
 * 报告里的 `checkpoint` 可能是别的机器的绝对路径
 * （如 `D:/somewhere/ScanMan/outputs/.../best`），
 * 全展示会撑爆布局，且对看的人也没信息量。
 */
export function shortPath(p: string | null | undefined, keep = 2): string {
  if (!p) return '—'
  const parts = p.replace(/\\/g, '/').split('/').filter(Boolean)
  if (parts.length <= keep) return parts.join('/')
  return `…/${parts.slice(-keep).join('/')}`
}

/**
 * 给 CWE 标签挑一个颜色。
 *
 * 按类别的**序号**稳定映射到一组颜色，而不是按概率 ——
 * 同一个 CWE 在页面各处应该颜色一致，这样扫一眼就能对上。
 * `OTHER` 单独给灰色（它是「长尾杂项」，语义上不该和具体 CWE 抢眼）。
 */
export function cweColor(cwe: string | undefined): string {
  if (!cwe) return 'default'
  if (cwe === 'OTHER') return 'default'
  const palette = [
    'red', 'volcano', 'orange', 'gold', 'lime',
    'green', 'cyan', 'blue', 'geekblue', 'purple', 'magenta',
  ]
  let h = 0
  for (let i = 0; i < cwe.length; i++) {
    h = (h * 31 + cwe.charCodeAt(i)) >>> 0
  }
  return palette[h % palette.length]
}
