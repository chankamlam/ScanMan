import { useMemo, useState } from 'react'
import type { FileResult, FunctionInfo } from '../types'

/**
 * 风险谱带 —— 这一页唯一被允许"用力"的元素。
 *
 * 把整次扫描压成一条横带：**每个函数是一根竖条，高度就是模型的漏洞概率**，
 * 按文件、按行号排开。一眼能看完整个项目的风险分布 —— 哪几个文件扎堆、
 * 有几个刚好卡在阈值线上、有没有一片全是低矮的安全区。
 *
 * 为什么做成谱带而不是饼图/环形图：这个项目的对象是**源码**，
 * 它的天然顺序就是"文件 → 行号"。饼图会把这个顺序丢掉，
 * 而顺序恰恰是看代码的人最需要的信息（"问题集中在哪个文件"）。
 *
 * 那条虚线是判定阈值 —— 越过它的函数才会被判为有漏洞。
 * 把决策边界画出来，比只给一个数字诚实得多。
 */

interface Item {
  file: string
  fn: FunctionInfo
  prob: number
  fileIndex: number
}

/** 两个十六进制颜色之间线性插值。t=0 取 a，t=1 取 b。 */
function lerpColor(a: string, b: string, t: number): string {
  const pa = [1, 3, 5].map((i) => parseInt(a.slice(i, i + 2), 16))
  const pb = [1, 3, 5].map((i) => parseInt(b.slice(i, i + 2), 16))
  const p = pa.map((v, i) => Math.round(v + (pb[i] - v) * t))
  return `rgb(${p[0]}, ${p[1]}, ${p[2]})`
}

export function RiskStrip({
  files,
  threshold,
  selectedKey,
  onSelect,
}: {
  files: FileResult[]
  threshold: number
  /** 当前选中的函数，形如 `文件名::函数名::起始行` */
  selectedKey?: string
  onSelect: (file: string, fn: FunctionInfo) => void
}) {
  const [hover, setHover] = useState<Item | null>(null)

  const items = useMemo<Item[]>(
    () =>
      files.flatMap((fr, fi) =>
        fr.functions
          .filter((f) => 'prob_vulnerable' in f)
          .map((f) => ({
            file: fr.path,
            fn: f,
            prob: f.prob_vulnerable ?? 0,
            fileIndex: fi,
          })),
      ),
    [files],
  )

  // 没有跑推理（报告里没有概率）时整条带子不显示 —— 不给空壳留位置
  if (items.length === 0) return null

  const H = 56 // 谱带净高
  const flagged = items.filter((i) => i.prob >= threshold).length

  return (
    <section
      aria-label={`风险谱带：${items.length} 个函数，${flagged} 个超过阈值`}
      style={{ borderTop: '1px solid var(--rule)', background: 'var(--surface)' }}
    >
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, padding: '10px 20px 4px' }}>
        <span className="eyebrow">风险谱带</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          纵轴 = 漏洞概率　·　虚线 = 判定阈值 {threshold.toFixed(2)}
        </span>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-2)' }}>
          <span style={{ color: 'var(--flag)', fontWeight: 500 }}>{flagged}</span>
          <span style={{ color: 'var(--ink-3)' }}> / {items.length} 越过阈值</span>
        </span>
      </div>

      {/* ---- 谱带本体 ---- */}
      <div style={{ position: 'relative', padding: '0 20px 14px' }}>
        {/* 阈值线：画在决策真正发生的高度上 */}
        <div
          aria-hidden
          style={{
            position: 'absolute',
            left: 20,
            right: 20,
            bottom: 14 + threshold * H,
            borderTop: '1px dashed var(--ink-3)',
            opacity: 0.55,
          }}
        />

        <div style={{ display: 'flex', alignItems: 'flex-end', height: H, gap: 9 }}>
          {files.map((fr, fi) => {
            const group = items.filter((i) => i.fileIndex === fi)
            if (group.length === 0) return null
            return (
              <div
                key={fr.path}
                style={{ display: 'flex', alignItems: 'flex-end', gap: 1, flex: group.length }}
                title={fr.path}
              >
                {group.map((it) => {
                  // 颜色按"离阈值多远"取：阈值以下走绿到灰，以上走橙到红。
                  // 用相对位置而不是绝对概率，是因为本项目概率整体偏低，
                  // 绝对映射会让整条带子糊成一片灰绿。
                  const t = Math.min(Math.max(it.prob / Math.max(threshold, 0.01), 0), 2) / 2
                  const color =
                    it.prob >= threshold
                      ? lerpColor('#b8730f', '#b02a1f', Math.min(t * 2 - 1, 1))
                      : lerpColor('#9fb3a9', '#2e6b52', it.prob / Math.max(threshold, 0.01))
                  const key = `${fr.path}::${it.fn.name}::${it.fn.start_line}`
                  const on = key === selectedKey
                  return (
                    <button
                      key={key}
                      onClick={() => onSelect(fr.path, it.fn)}
                      onMouseEnter={() => setHover(it)}
                      onMouseLeave={() => setHover(null)}
                      aria-label={`${fr.path} 第 ${it.fn.start_line} 行 ${it.fn.name}，漏洞概率 ${(it.prob * 100).toFixed(1)}%`}
                      style={{
                        // 高度编码概率 —— 这是这条带子唯一的信息通道
                        height: Math.max(3, it.prob * H),
                        flex: 1,
                        minWidth: 3,
                        padding: 0,
                        border: 'none',
                        // 选中的那根用描边标出来，而不是换颜色（颜色已经被概率占用了）
                        outline: on ? '2px solid var(--signal)' : 'none',
                        outlineOffset: 1,
                        background: color,
                        cursor: 'pointer',
                        borderRadius: '1px 1px 0 0',
                        transition: 'opacity .12s',
                        opacity: hover && hover !== it ? 0.45 : 1,
                      }}
                    />
                  )
                })}
              </div>
            )
          })}
        </div>

        {/* 悬停读数：贴在带子下面，位置固定，避免跟着鼠标抖动 */}
        <div
          style={{
            height: 18,
            marginTop: 6,
            fontSize: 11,
            fontFamily: 'var(--font-mono)',
            color: 'var(--ink-2)',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {hover ? (
            <>
              <span style={{ color: 'var(--ink-3)' }}>
                {hover.file}:{hover.fn.start_line}
              </span>{' '}
              <span style={{ color: 'var(--ink)' }}>{hover.fn.name}</span>{' '}
              <span
                style={{
                  color: hover.prob >= threshold ? 'var(--flag)' : 'var(--ok)',
                  fontWeight: 500,
                }}
              >
                {(hover.prob * 100).toFixed(1)}%
              </span>
            </>
          ) : (
            <span style={{ color: 'var(--ink-3)' }}>把鼠标移到竖条上看具体函数</span>
          )}
        </div>
      </div>
    </section>
  )
}
