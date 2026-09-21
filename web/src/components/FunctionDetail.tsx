import { useEffect, useMemo, useRef } from 'react'
import Prism from 'prismjs'
import 'prismjs/themes/prism.css'

// ⚠️ 语言包必须**按依赖顺序**手动加载。
// npm 版的 prismjs 组件文件不会自动拉自己的依赖，而 prism-c 的语法写的是
// `Prism.languages.extend('clike', ...)` —— 少了 prism-clike，
// Prism.languages.c 就是 undefined，highlightElement 会在内部抛
// "Cannot read properties of undefined (reading 'tokenizePlaceholders')"，
// 而且**只在真正渲染代码块时才炸**，页面其它部分看起来完全正常。
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-c'
import 'prismjs/components/prism-cpp'
import 'prismjs/components/prism-javascript'
import 'prismjs/components/prism-typescript'
import 'prismjs/components/prism-python'
import 'prismjs/components/prism-markup-templating' // php 依赖它
import 'prismjs/components/prism-php'

import type { FunctionInfo, TopKItem } from '../types'

/**
 * 单个函数的分析结果。
 *
 * 左右分栏不是审美选择，是语义：**左边是证据（真实的源码和行号），
 * 右边是结论（模型的判定和依据）**。看代码的人需要能同时看到这两样。
 */
export function FunctionDetail({
  fn,
  file,
  language,
  threshold,
}: {
  fn: FunctionInfo
  file: string
  language: string
  /** 判定阈值。报告里没跑检测时为 null，此时刻度上不画判定线。 */
  threshold: number | null
}) {
  const hasCode = 'code' in fn && !!fn.code
  const hasVerdict = 'verdict' in fn
  const hasCwe = 'cwe' in fn && !!fn.cwe

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: hasCode ? 'minmax(0, 1.45fr) minmax(260px, 1fr)' : '1fr',
        gap: 20,
        alignItems: 'start',
      }}
    >
      {hasCode && <CodeBlock code={fn.code!} startLine={fn.start_line} language={language} file={file} />}

      <div>
        {/* ---- 检测 ---- */}
        <SectionLabel>检测判定</SectionLabel>
        {hasVerdict ? (
          <div style={{ marginBottom: 20 }}>
            <ProbScale value={fn.prob_vulnerable ?? 0} verdict={fn.verdict!} threshold={threshold} />
            {/*
              ⚠️ 这里**不能**写「原始置信度 {confidence}」。
              `confidence` 的含义随判定结果变化（见 types.ts 第 31-36 行）：
              判为 vulnerable 时它等于 p(漏洞)，判为 safe 时却是 p(安全) ——
              于是判为安全时页面上会出现「漏洞概率 62.5%」和「置信度 0.3751」
              两个数字并排，看起来互相矛盾。
              直接给两个互补的概率，语义唯一，怎么读都不会错。
            */}
            <div className="mono" style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 7 }}>
              原始输出 p(有漏洞) {fn.prob_vulnerable?.toFixed(4) ?? '—'}
              <span style={{ margin: '0 6px' }}>·</span>
              p(安全) {(1 - (fn.prob_vulnerable ?? 0)).toFixed(4)}
            </div>
          </div>
        ) : (
          <p style={{ color: 'var(--ink-3)', fontSize: 12, margin: '0 0 20px' }}>这份报告没有跑检测模型</p>
        )}

        {/* ---- 分类 ---- */}
        <SectionLabel>漏洞类型</SectionLabel>
        {hasCwe ? (
          <>
            <div style={{ marginBottom: 12 }}>
              <span
                className="mono"
                style={{
                  fontSize: 14,
                  fontWeight: 500,
                  letterSpacing: '0.01em',
                  padding: '2px 9px',
                  borderRadius: 2,
                  background: 'var(--flag-bg)',
                  color: 'var(--flag)',
                }}
              >
                {fn.cwe}
              </span>
            </div>
            <TopK items={fn.cwe_topk ?? []} />
          </>
        ) : (
          <p style={{ color: 'var(--ink-3)', fontSize: 12, margin: 0 }}>
            {fn.verdict === 'vulnerable' ? '这份报告没有跑分类模型' : '分类只对判为有漏洞的函数执行'}
          </p>
        )}
      </div>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="eyebrow" style={{ marginBottom: 8, paddingBottom: 5, borderBottom: '1px solid var(--rule-soft)' }}>
      {children}
    </div>
  )
}

/* -------------------------------------------------------------- 源码块 */

/**
 * 源码，带**真实行号**和语法高亮。
 *
 * 行号从报告里的 `start_line` 起算 —— 抽取器已经给了文件里的真实行号，
 * 前端不能从 1 重新数（那样和源文件对不上，看的人没法按图索骥）。
 */
function CodeBlock({
  code,
  startLine,
  language,
  file,
}: {
  code: string
  startLine: number
  language: string
  file: string
}) {
  const ref = useRef<HTMLElement>(null)

  const prismLang = useMemo(() => {
    const m: Record<string, string> = {
      c: 'c',
      cpp: 'cpp',
      python: 'python',
      javascript: 'javascript',
      typescript: 'typescript',
      tsx: 'typescript',
      php: 'php',
    }
    return m[language] ?? 'clike'
  }, [language])

  useEffect(() => {
    if (!ref.current) return
    // 防御：扫到没加载语言包的文件时 Prism 会抛异常，
    // 而 useEffect 里的异常会冒泡成运行时错误、把整个面板搞白。
    // 宁可不高亮，也不能崩。
    if (!Prism.languages[prismLang]) return
    Prism.highlightElement(ref.current)
  }, [code, prismLang])

  const lines = code.split('\n')

  return (
    <div>
      {/* 文件名条：把这段代码属于哪个文件写在最上面，和列表里的路径呼应 */}
      <div
        className="mono"
        style={{
          fontSize: 10.5,
          color: 'var(--ink-3)',
          padding: '0 0 5px',
          letterSpacing: '0.02em',
        }}
      >
        {file}
      </div>

      <div
        style={{
          display: 'flex',
          maxHeight: 460,
          overflow: 'auto',
          background: 'var(--surface-2)',
          border: '1px solid var(--rule)',
          borderRadius: 'var(--r)',
        }}
      >
        {/* 行号栏 */}
        <div
          className="mono"
          aria-hidden
          style={{
            padding: '9px 9px 9px 11px',
            textAlign: 'right',
            color: 'var(--ink-3)',
            fontSize: 11,
            lineHeight: '17px',
            userSelect: 'none',
            background: '#f2f4f3',
            borderRight: '1px solid var(--rule)',
            flexShrink: 0,
          }}
        >
          {lines.map((_, i) => (
            <div key={i}>{startLine + i}</div>
          ))}
        </div>
        {/* 代码 */}
        <pre
          style={{
            margin: 0,
            padding: '9px 12px',
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            lineHeight: '17px',
            flex: 1,
            minWidth: 0,
            overflowX: 'auto',
          }}
        >
          <code ref={ref} className={`language-${prismLang}`}>
            {code}
          </code>
        </pre>
      </div>
    </div>
  )
}

/* ---------------------------------------------------------- 概率刻度 */

/**
 * 漏洞概率，画成一条**带阈值的刻度**。
 *
 * 关键差别：这条刻度上标出了判定阈值的位置。单给一个 "86.4%" 看不出
 * 它离判定线有多远；标出来之后，"刚好压线"和"远超阈值"一眼可辨。
 */
function ProbScale({
  value,
  verdict,
  threshold,
}: {
  value: number
  verdict: string
  threshold: number | null
}) {
  const vul = verdict === 'vulnerable'
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span
          className="mono"
          style={{
            fontSize: 26,
            fontWeight: 500,
            letterSpacing: '-0.03em',
            lineHeight: 1,
            color: vul ? 'var(--flag)' : 'var(--ok)',
          }}
        >
          {(value * 100).toFixed(1)}
          <span style={{ fontSize: 14, marginLeft: 1 }}>%</span>
        </span>
        <span className="eyebrow">漏洞概率</span>
      </div>

      {/* 刻度上必须**真的画出判定线** —— 光写一句"超过阈值判为有漏洞"
          而线不在，读的人没法判断这个概率离判定边界有多远。 */}
      <div style={{ position: 'relative', height: 7, marginTop: 11 }}>
        <div style={{ position: 'absolute', inset: 0, background: 'var(--rule-soft)', borderRadius: 1 }} />
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: `${Math.min(value * 100, 100)}%`,
            background: vul ? 'var(--flag)' : 'var(--ok)',
            borderRadius: 1,
          }}
        />
        {threshold !== null && threshold <= 1 && (
          <div
            title={`判定阈值 ${threshold.toFixed(3)}`}
            style={{
              position: 'absolute',
              left: `${threshold * 100}%`,
              top: -4,
              bottom: -4,
              width: 1,
              background: 'var(--ink)',
            }}
          />
        )}
      </div>

      <div
        className="mono"
        style={{ fontSize: 10, color: 'var(--ink-3)', marginTop: 4, position: 'relative', height: 13 }}
      >
        <span style={{ position: 'absolute', left: 0 }}>0</span>
        {threshold !== null && (
          <span
            style={{
              position: 'absolute',
              left: `${threshold * 100}%`,
              transform: 'translateX(-50%)',
              color: 'var(--ink-2)',
              whiteSpace: 'nowrap',
            }}
          >
            ▲ 阈值 {threshold.toFixed(2)}
          </span>
        )}
        <span style={{ position: 'absolute', right: 0 }}>100%</span>
      </div>
    </div>
  )
}

/* --------------------------------------------------------- Top-K 候选 */

/**
 * CWE 的 Top-N 候选。
 *
 * 这是整份报告里信息密度最高的一个字段 —— 它把"模型有多确定"变成了
 * 看得见的东西。两个必须注意的地方：
 *
 *   1. 条长按**本组内最大值**归一化，不能按绝对概率画。27 类模型下
 *      Top-1 的概率经常只有 0.1 出头，按绝对值画全是空条。
 *   2. 候选条数不固定（是 min(5, 类别数)），不要硬编码 5。
 */
function TopK({ items }: { items: TopKItem[] }) {
  if (items.length === 0) {
    return <p style={{ color: 'var(--ink-3)', fontSize: 12, margin: 0 }}>没有候选</p>
  }
  const max = Math.max(...items.map((i) => i.prob), 1e-9)

  return (
    <div>
      <div className="mono" style={{ fontSize: 10.5, color: 'var(--ink-3)', marginBottom: 6 }}>
        候选 {items.length} 个 · 条长按组内最大值归一化
      </div>
      {items.map((it, i) => (
        <div key={it.cwe} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span className="mono" style={{ fontSize: 10.5, color: 'var(--ink-3)', width: 14, textAlign: 'right' }}>
            {i + 1}
          </span>
          <span
            className="mono"
            style={{
              fontSize: 11,
              width: 62,
              color: i === 0 ? 'var(--ink)' : 'var(--ink-2)',
              fontWeight: i === 0 ? 500 : 400,
            }}
          >
            {it.cwe}
          </span>
          <span style={{ flex: 1, height: 5, background: 'var(--rule-soft)', borderRadius: 1, overflow: 'hidden', minWidth: 30 }}>
            <span
              style={{
                display: 'block',
                width: `${(it.prob / max) * 100}%`,
                height: '100%',
                background: i === 0 ? 'var(--ink)' : '#b9c2c7',
              }}
            />
          </span>
          <span
            className="mono"
            style={{
              fontSize: 10.5,
              color: 'var(--ink-3)',
              width: 42,
              textAlign: 'right',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {(it.prob * 100).toFixed(1)}%
          </span>
        </div>
      ))}
    </div>
  )
}
