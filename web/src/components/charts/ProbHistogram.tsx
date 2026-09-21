import { useMemo } from 'react'

import type { FileResult } from '../../types'
import { pct } from '../../format'
import {
  CHART,
  ChartCard,
  ChartEmpty,
  ChartTip,
  GAP,
  Legend,
  tipHostStyle,
  useChartTip,
  useMeasure,
} from './chartkit'

/**
 * 漏洞概率分布直方图（带判定阈值线）。
 *
 * 这张图回答的是**「模型有多确信」**：把每个函数的漏洞概率分箱计数，
 * 一眼看出结论是集中在两端（很有把握），还是堆在阈值附近（其实都在犹豫）。
 *
 * 两个刻意的设计：
 *
 * 1. **每根柱子按真实的 `verdict` 拆成两段**（安全 / 有漏洞），而不是
 *    "左半边绿、右半边红"。因为一个箱里可能同时有安全和漏洞两种函数 ——
 *    按箱子的位置涂色会把这件事抹掉。用真实判定着色，再拿阈值线去解释
 *    「为什么分界在这里」，这才是诚实的画法。
 *
 * 2. **阈值线用虚线**。这里和别处相反：网格线一律实线（虚线会被误读成阈值），
 *    而这条线**就是**阈值，虚线恰好是它的正确语言。
 */
const BINS = 10
const H = 150 // 绘图区净高
const PAD = { l: 34, r: 10, t: 10, b: 26 }

export function ProbHistogram({
  files,
  threshold,
}: {
  files: FileResult[]
  threshold: number | null
}) {
  const [ref, width] = useMeasure<HTMLDivElement>()
  const { tip, setTip, onMouseLeave } = useChartTip()

  const items = useMemo(
    () =>
      files.flatMap((fr) =>
        fr.functions
          .filter((f) => 'prob_vulnerable' in f)
          .map((f) => ({
            prob: f.prob_vulnerable ?? 0,
            vul: f.verdict === 'vulnerable',
          })),
      ),
    [files],
  )

  const bins = useMemo(() => {
    const out = Array.from({ length: BINS }, (_, i) => ({
      lo: i / BINS,
      hi: (i + 1) / BINS,
      safe: 0,
      vuln: 0,
    }))
    for (const it of items) {
      // 概率恰好 =1 时 clamp 进最后一箱
      const i = Math.min(BINS - 1, Math.floor(it.prob * BINS))
      if (it.vul) out[i].vuln++
      else out[i].safe++
    }
    return out
  }, [items])

  if (items.length === 0) {
    return (
      <ChartCard title="漏洞概率分布">
        <ChartEmpty>这份报告没有跑检测模型，拿不到概率</ChartEmpty>
      </ChartCard>
    )
  }

  const maxTotal = Math.max(1, ...bins.map((b) => b.safe + b.vuln))
  const yMax = niceCeil(maxTotal)

  const plotW = Math.max(120, width - PAD.l - PAD.r)
  const slot = plotW / BINS
  // 柱子不铺满槽位 —— 留白让相邻箱子读起来是各自独立的
  const bw = Math.min(24, Math.max(6, slot - GAP - 2))
  const y = (v: number) => H - (v / yMax) * H

  const thX =
    threshold !== null && threshold >= 0 && threshold <= 1
      ? PAD.l + threshold * plotW
      : null

  return (
    <ChartCard
      title="漏洞概率分布"
      subtitle={
        <>
          每根柱 = 该概率区间的函数数，按模型的实际判定拆色
          {threshold !== null && (
            <>
              {'　·　'}虚线 = 判定阈值 <b>{pct(threshold, 1)}</b>
              （越过它才判为有漏洞）
            </>
          )}
        </>
      }
      right={
        <Legend
          items={[
            { color: CHART.ok, label: '判定为安全' },
            { color: CHART.flag, label: '判定为有漏洞' },
          ]}
        />
      }
    >
      <div ref={ref} style={tipHostStyle} onMouseLeave={onMouseLeave}>
        {width > 0 && (
          <svg
            width={width}
            height={H + PAD.t + PAD.b}
            role="img"
            aria-label={`漏洞概率分布直方图，共 ${items.length} 个函数`}
            onMouseLeave={onMouseLeave}
          >
            {/* ---- 网格与刻度 ---- */}
            {ticks(yMax).map((v) => (
              <g key={v}>
                <line
                  x1={PAD.l}
                  x2={PAD.l + plotW}
                  y1={PAD.t + y(v)}
                  y2={PAD.t + y(v)}
                  stroke={v === 0 ? CHART.axis : CHART.grid}
                  strokeWidth={1}
                  shapeRendering="crispEdges"
                />
                <text
                  x={PAD.l - 6}
                  y={PAD.t + y(v) + 3.5}
                  textAnchor="end"
                  fontSize={10}
                  fill={CHART.muted}
                  style={{ fontVariantNumeric: 'tabular-nums' }}
                >
                  {v}
                </text>
              </g>
            ))}

            {/* ---- 柱子 ---- */}
            {bins.map((b, i) => {
              const cx = PAD.l + i * slot + slot / 2
              const x = cx - bw / 2
              const total = b.safe + b.vuln
              const hSafe = (b.safe / yMax) * H
              const hVuln = (b.vuln / yMax) * H
              // 两段之间留表面色的缝；只有一段时不留
              const both = b.safe > 0 && b.vuln > 0
              const gap = both ? GAP : 0
              const ySafeTop = PAD.t + H - hSafe
              const yVulnTop = ySafeTop - gap - hVuln

              return (
                <g key={i}>
                  {/* 悬停热区盖满整列，不要求鼠标精确落在柱子上 */}
                  <rect
                    x={PAD.l + i * slot}
                    y={PAD.t}
                    width={slot}
                    height={H}
                    fill="transparent"
                    onMouseMove={(e) => {
                      const box = e.currentTarget.ownerSVGElement!.getBoundingClientRect()
                      setTip({
                        x: e.clientX - box.left,
                        y: e.clientY - box.top,
                        node: (
                          <>
                            <div style={{ color: '#c9d2d8' }}>
                              {pct(b.lo, 0)} – {pct(b.hi, 0)}
                            </div>
                            <div style={{ color: '#fff' }}>
                              共 {total} 个
                            </div>
                            <div style={{ color: '#7fd3ac' }}>安全 {b.safe}</div>
                            <div style={{ color: '#f0a39b' }}>有漏洞 {b.vuln}</div>
                          </>
                        ),
                      })
                    }}
                  />

                  {/* 安全段。上面还压着漏洞段时顶端要方（留缝给表面色），
                      否则它自己就是数据末端，要圆角。 */}
                  {b.safe > 0 &&
                    (both ? (
                      <rect
                        x={x}
                        y={ySafeTop}
                        width={bw}
                        height={hSafe}
                        fill={CHART.ok}
                        pointerEvents="none"
                      />
                    ) : (
                      <path
                        d={topRounded(x, ySafeTop, bw, hSafe)}
                        fill={CHART.ok}
                        pointerEvents="none"
                      />
                    ))}
                  {/* 漏洞段永远在最上面，永远是数据末端 */}
                  {b.vuln > 0 && (
                    <path
                      d={topRounded(x, yVulnTop, bw, hVuln)}
                      fill={CHART.flag}
                      pointerEvents="none"
                    />
                  )}
                </g>
              )
            })}

            {/* ---- 阈值线 ---- */}
            {thX !== null && (
              <g pointerEvents="none">
                <line
                  x1={thX}
                  x2={thX}
                  y1={PAD.t - 4}
                  y2={PAD.t + H}
                  stroke={CHART.ink}
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                />
                <text
                  x={thX}
                  y={PAD.t - 6}
                  textAnchor={threshold! > 0.8 ? 'end' : 'middle'}
                  fontSize={10}
                  fill={CHART.ink}
                  style={{ fontVariantNumeric: 'tabular-nums' }}
                >
                  阈值 {pct(threshold!, 1)}
                </text>
              </g>
            )}

            {/* ---- x 轴 ---- */}
            <line
              x1={PAD.l}
              x2={PAD.l + plotW}
              y1={PAD.t + H}
              y2={PAD.t + H}
              stroke={CHART.axis}
              strokeWidth={1}
              shapeRendering="crispEdges"
            />
            {[0, 0.2, 0.4, 0.6, 0.8, 1].map((t) => (
              <text
                key={t}
                x={PAD.l + t * plotW}
                y={PAD.t + H + 14}
                textAnchor={t === 0 ? 'start' : t === 1 ? 'end' : 'middle'}
                fontSize={10}
                fill={CHART.muted}
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {pct(t, 0)}
              </text>
            ))}
          </svg>
        )}
        <ChartTip tip={tip} width={width} />
      </div>
    </ChartCard>
  )
}

/* ---------------------------------------------------------------- 工具 */

/** 顶端圆角、底端方角的竖向柱（数据从基线往上长）。 */
function topRounded(x: number, y: number, w: number, h: number, r = 4): string {
  if (h <= 0) return ''
  const rr = Math.min(r, w / 2, h)
  return [
    `M ${x} ${y + h}`,
    `V ${y + rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + rr} ${y}`,
    `H ${x + w - rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + w} ${y + rr}`,
    `V ${y + h}`,
    'Z',
  ].join(' ')
}

/** 把上界取整到好看的数（刻度上不该出现 7、13 这种数）。 */
function niceCeil(n: number): number {
  if (n <= 5) return n // 计数很小的时候，原样就是最好读的
  const pow = Math.pow(10, Math.floor(Math.log10(n)))
  const d = n / pow
  const step = d <= 1 ? 1 : d <= 2 ? 2 : d <= 5 ? 5 : 10
  return step * pow
}

/** 只画 0 和上界两条，中间的刻度对计数图来说没必要（柱子自己会说话）。 */
function ticks(yMax: number): number[] {
  return yMax <= 1 ? [0, 1] : [0, yMax]
}
