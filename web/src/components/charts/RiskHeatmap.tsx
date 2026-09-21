import { useMemo } from 'react'

import type { FileRow } from '../../rows'
import { pct } from '../../format'
import {
  CHART,
  ChartCard,
  ChartEmpty,
  ChartTip,
  rampAt,
  tipHostStyle,
  useChartTip,
  useMeasure,
} from './chartkit'

/**
 * 文件 × 概率分档 热力图。
 *
 * 这张图回答的是前几张都答不了的问题：**「这个文件的问题是集中在高置信度，
 * 还是全堆在阈值附近模棱两可？」** 直方图把它按概率摊平了（看不出是哪个文件），
 * 排行条把它按文件摊平了（看不出把握多大），只有网格能同时留住这两个维度。
 *
 * 编码用**单一蓝色顺序色阶**（浅→深 = 少→多），不是彩虹，也不是按箱子位置涂红绿 ——
 * 量级就该用一个色相表达。0 个的格子留白（表面色），那是"没有"，不是"最浅的一档"。
 */
const COLS = 5 // 5 档：0-20% … 80-100%
const CELL_H = 26
const GAP = 2
const HEAD_H = 18

export function RiskHeatmap({
  rows,
  threshold,
  selectedId,
  onSelect,
}: {
  rows: FileRow[]
  threshold: number | null
  selectedId?: string
  onSelect: (client_id: string) => void
}) {
  const [ref, width] = useMeasure<HTMLDivElement>()
  const { tip, setTip, onMouseLeave } = useChartTip()

  const data = useMemo(() => {
    const out = rows
      .filter((r) => r.file?.functions.some((f) => 'prob_vulnerable' in f))
      .map((r) => {
        const cells = Array.from({ length: COLS }, () => 0)
        for (const f of r.file!.functions) {
          if (!('prob_vulnerable' in f)) continue
          const p = f.prob_vulnerable ?? 0
          cells[Math.min(COLS - 1, Math.floor(p * COLS))]++
        }
        return { row: r, cells, total: cells.reduce((a, b) => a + b, 0) }
      })
      .sort((a, b) => b.total - a.total || a.row.displayName.localeCompare(b.row.displayName))
    return out
  }, [rows])

  if (data.length === 0) {
    return (
      <ChartCard title="文件 × 概率分档">
        <ChartEmpty>这份报告没有跑检测模型，拿不到概率</ChartEmpty>
      </ChartCard>
    )
  }

  const max = Math.max(1, ...data.flatMap((d) => d.cells))
  const labelW = Math.max(76, Math.min(170, width * 0.3))
  const gridW = Math.max(120, width - labelW)
  const cellW = (gridW - GAP * (COLS - 1)) / COLS
  const height = HEAD_H + data.length * (CELL_H + GAP)

  // 阈值落在哪一档 —— 给那一列加个标记，把"决策边界在哪"标出来
  const thCol =
    threshold !== null && threshold >= 0 && threshold <= 1
      ? Math.min(COLS - 1, Math.floor(threshold * COLS))
      : null

  return (
    <ChartCard
      title="文件 × 概率分档"
      subtitle={
        <>
          每格 = 落在该概率区间的函数数，颜色越深越多
          {threshold !== null && (
            <>
              {'　·　'}▼ 标出阈值 <b>{pct(threshold, 0)}</b> 所在的那一档
            </>
          )}
        </>
      }
    >
      <div ref={ref} style={tipHostStyle} onMouseLeave={onMouseLeave}>
        {width > 0 && (
          <svg
            width={width}
            height={height}
            role="img"
            aria-label="文件与概率分档的分布矩阵"
            onMouseLeave={onMouseLeave}
          >
            {/* ---- 列头 ---- */}
            {Array.from({ length: COLS }, (_, c) => (
              <text
                key={c}
                x={labelW + c * (cellW + GAP) + cellW / 2}
                y={11}
                textAnchor="middle"
                fontSize={10}
                fill={c === thCol ? CHART.ink : CHART.muted}
                fontWeight={c === thCol ? 600 : 400}
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {pct(c / COLS, 0)}–{pct((c + 1) / COLS, 0)}
              </text>
            ))}
            {thCol !== null && (
              <path
                d={`M ${labelW + thCol * (cellW + GAP) + cellW / 2 - 3.5} 14
                    L ${labelW + thCol * (cellW + GAP) + cellW / 2 + 3.5} 14
                    L ${labelW + thCol * (cellW + GAP) + cellW / 2} 17.5 Z`}
                fill={CHART.ink}
              />
            )}

            {/* ---- 格子 ---- */}
            {data.map((d, r) => (
              <g key={d.row.client_id}>
                <text
                  x={labelW - 10}
                  y={HEAD_H + r * (CELL_H + GAP) + CELL_H / 2 + 3.5}
                  textAnchor="end"
                  fontSize={12}
                  fill={
                    d.row.client_id === selectedId ? 'var(--ink)' : 'var(--ink-2)'
                  }
                  style={{ fontFamily: 'var(--font-mono)' }}
                >
                  {clip(d.row.displayName, labelW - 16)}
                </text>

                {d.cells.map((n, c) => {
                  const x = labelW + c * (cellW + GAP)
                  const y = HEAD_H + r * (CELL_H + GAP)
                  // 0 是"没有"，用表面色 —— 不是色阶里最浅的那一档
                  const fill = n === 0 ? CHART.surface : rampAt((n - 1) / Math.max(1, max - 1))
                  const dark = n > 0 && (n - 1) / Math.max(1, max - 1) >= 0.4
                  return (
                    <g key={c}>
                      <rect
                        x={x}
                        y={y}
                        width={cellW}
                        height={CELL_H}
                        fill={fill}
                        stroke={n === 0 ? CHART.grid : 'none'}
                        strokeWidth={1}
                        style={{ cursor: 'pointer' }}
                        onClick={() => onSelect(d.row.client_id)}
                        onMouseMove={(e) => {
                          const box =
                            e.currentTarget.ownerSVGElement!.getBoundingClientRect()
                          setTip({
                            x: e.clientX - box.left,
                            y: e.clientY - box.top,
                            node: (
                              <>
                                <div style={{ color: '#fff' }}>{d.row.displayName}</div>
                                <div style={{ color: '#c9d2d8' }}>
                                  {pct(c / COLS, 0)}–{pct((c + 1) / COLS, 0)}：{n} 个
                                </div>
                                <div style={{ color: '#c9d2d8' }}>
                                  该文件共 {d.total} 个函数
                                </div>
                              </>
                            ),
                          })
                        }}
                      />
                      {n > 0 && (
                        <text
                          x={x + cellW / 2}
                          y={y + CELL_H / 2 + 3.5}
                          textAnchor="middle"
                          fontSize={11}
                          // 填色块上的文字按明度取白或墨，保证任何一档都读得清
                          fill={dark ? '#fff' : CHART.ink}
                          pointerEvents="none"
                          style={{ fontWeight: 500 }}
                        >
                          {n}
                        </text>
                      )}
                    </g>
                  )
                })}
              </g>
            ))}
          </svg>
        )}
        <ChartTip tip={tip} width={width} />
      </div>
    </ChartCard>
  )
}

/** 与 FileRiskRanking 里同款的等宽字体粗略截断。 */
function clip(s: string, maxPx: number): string {
  const max = Math.max(6, Math.floor(maxPx / 7.2))
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}
