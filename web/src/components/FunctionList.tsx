import { useMemo, useState } from 'react'

import type { FileResult, FunctionInfo } from '../types'
import { pct } from '../format'
import { sortFunctions } from '../rows'
import { cweName } from '../cwe'
import { CHART } from './charts/chartkit'

/**
 * 一个文件里的函数清单。
 *
 * **这个组件是 `FunctionDetail` 的唯一入口** —— 删掉老的 `FileTable` 之后，
 * 如果没有它，就没有任何东西负责「列出某个文件有哪些函数」，
 * 那个做得最好的源码/判定对照面板会变成点不到的死代码。
 *
 * 下钻链是：聚合图（热力图 / 风险排行）→ 选中文件 → 这张表 → 点某个函数 → 源码和判定。
 */
export function FunctionList({
  file,
  fileLabel,
  threshold,
  selected,
  onSelect,
}: {
  file: FileResult
  fileLabel: string
  threshold: number | null
  selected: FunctionInfo | null
  onSelect: (fn: FunctionInfo) => void
}) {
  // 默认按漏洞概率降序 —— 看报告的人最想知道"最该先看哪个"
  const [byProb, setByProb] = useState(true)
  const fns = useMemo(() => sortFunctions(file.functions, byProb), [file.functions, byProb])

  if (file.functions.length === 0) {
    return (
      <div style={{ padding: 20, fontSize: 12, color: 'var(--ink-3)' }}>
        这个文件里没有抽到函数
        {file.function_count === 0 && file.functions_discarded > 0 && (
          <>（有 {file.functions_discarded} 个因为语法错误被丢弃）</>
        )}
      </div>
    )
  }

  return (
    <div>
      {/* ---- 表头 ---- */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '10px 16px',
          borderBottom: '1px solid var(--rule)',
          flexWrap: 'wrap',
        }}
      >
        <span className="eyebrow">函数</span>
        <span className="mono" style={{ fontSize: 12 }}>
          {fileLabel}
        </span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          {file.functions.length} 个
        </span>
        <span style={{ flex: 1 }} />
        <label
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 11,
            color: 'var(--ink-3)',
            cursor: 'pointer',
            userSelect: 'none',
          }}
        >
          <input
            type="checkbox"
            checked={byProb}
            onChange={(e) => setByProb(e.target.checked)}
            style={{ accentColor: 'var(--signal)', margin: 0 }}
          />
          按概率排序（否则按行号）
        </label>
      </div>

      {/* ---- 列头 ---- */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '56px minmax(0,1fr) 88px 44px',
          gap: 10,
          padding: '6px 16px',
          background: 'var(--surface-2)',
          borderBottom: '1px solid var(--rule-soft)',
        }}
        className="mono"
      >
        {['行', '函数名', '漏洞概率', '类型'].map((h) => (
          <span key={h} className="eyebrow">
            {h}
          </span>
        ))}
      </div>

      {/* ---- 行 ---- */}
      {fns.map((fn) => {
        const on =
          selected?.name === fn.name && selected?.start_line === fn.start_line
        const prob = fn.prob_vulnerable
        const vul = fn.verdict === 'vulnerable'
        const overTh = prob !== undefined && threshold !== null && prob >= threshold
        const name = cweName(fn.cwe)

        return (
          <button
            key={`${fn.name}::${fn.start_line}`}
            onClick={() => onSelect(fn)}
            style={{
              display: 'grid',
              gridTemplateColumns: '56px minmax(0,1fr) 88px 44px',
              gap: 10,
              alignItems: 'center',
              width: '100%',
              textAlign: 'left',
              padding: '6px 16px',
              border: 'none',
              borderBottom: '1px solid var(--rule-soft)',
              borderLeft: on ? '2px solid var(--signal)' : '2px solid transparent',
              background: on ? '#f4f7fb' : 'transparent',
              cursor: 'pointer',
            }}
            className="fn-row"
          >
            <span
              className="mono"
              style={{ fontSize: 11, color: 'var(--ink-3)', fontVariantNumeric: 'tabular-nums' }}
            >
              {fn.start_line}
            </span>

            <span style={{ minWidth: 0, display: 'flex', alignItems: 'center', gap: 7 }}>
              <span
                className="mono"
                style={{
                  fontSize: 12.5,
                  color: 'var(--ink)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {fn.name}
              </span>
              {fn.depth > 0 && (
                <span
                  className="mono"
                  style={{ fontSize: 10, color: 'var(--ink-3)', flexShrink: 0 }}
                  title={fn.parent_name ? `嵌套在 ${fn.parent_name} 里` : '嵌套函数'}
                >
                  ↳
                </span>
              )}
            </span>

            {/* 概率：条 + 数字。没有概率（未跑检测）就不画空条 */}
            {prob === undefined ? (
              <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
                —
              </span>
            ) : (
              <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span
                  style={{
                    flex: 1,
                    height: 4,
                    background: 'var(--rule-soft)',
                    borderRadius: 2,
                    overflow: 'hidden',
                    minWidth: 18,
                  }}
                >
                  <span
                    style={{
                      display: 'block',
                      width: `${Math.min(prob, 1) * 100}%`,
                      height: '100%',
                      background: overTh ? CHART.flag : CHART.ok,
                    }}
                  />
                </span>
                <span
                  className="mono"
                  style={{
                    fontSize: 11,
                    color: overTh ? 'var(--flag)' : 'var(--ink-3)',
                    fontVariantNumeric: 'tabular-nums',
                    width: 38,
                    textAlign: 'right',
                  }}
                >
                  {pct(prob)}
                </span>
              </span>
            )}

            {/* CWE：没跑分类时不写「安全」—— 那是两码事 */}
            {fn.cwe ? (
              <span
                className="mono"
                style={{
                  fontSize: 10.5,
                  color: 'var(--ink-2)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
                title={name ? `${fn.cwe} ${name}` : fn.cwe}
              >
                {fn.cwe}
              </span>
            ) : (
              <span
                className="mono"
                style={{ fontSize: 10.5, color: vul ? 'var(--ink-3)' : 'var(--ok)' }}
              >
                {fn.verdict === undefined ? '—' : vul ? '—' : '安全'}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
