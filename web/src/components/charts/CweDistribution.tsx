import { useMemo } from 'react'

import type { ScanReport } from '../../types'
import { CWE_NAMES, cweName } from '../../cwe'
import {
  CHART,
  ChartCard,
  ChartEmpty,
  ChartTip,
  barPath,
  tipHostStyle,
  useChartTip,
  useMeasure,
} from './chartkit'

/**
 * CWE 漏洞类型分布。
 *
 * 三个刻意的选择：
 *
 * 1. **横向条形，不是饼图/环形图**。类别多了以后，饼图里那些都等于 1 的
 *    切片根本分不出大小 —— 而"平手"恰恰是这个场景的常态。
 *    条形图对平手是诚实的，顺带把类别名和计数直接写在了图上（等于自带表格视图）。
 *
 * 2. **单色**。类别是**名义**的（`CWE-119` 不比 `CWE-89` 更"大"），
 *    给每个类别配一个颜色会让颜色去暗示不存在的顺序，而且很快撞到
 *    "8 个色以上就分不清"的天花板。长度已经是唯一的量级通道了。
 *
 * 3. **中文简称**。项目里原本没有 CWE→中文名的映射（见 `src/cwe.ts`），
 *    但「CWE-119 缓冲区溢出」比光秃秃一个编号可读得多。
 */
const ROW_H = 24
const BAR_H = 14
/** 一张卡片里最多画几类。超出的**显式说明**，不静默截断。 */
const MAX_ROWS = 12

interface Slice {
  cwe: string
  count: number
}

export function CweDistribution({ report }: { report: ScanReport }) {
  const [ref, width] = useMeasure<HTMLDivElement>()
  const { tip, setTip, onMouseLeave } = useChartTip()

  const { slices, hidden } = useMemo(() => {
    const counts = new Map<string, number>()
    for (const fr of report.files) {
      for (const f of fr.functions) {
        if (f.cwe) counts.set(f.cwe, (counts.get(f.cwe) ?? 0) + 1)
      }
    }
    const all: Slice[] = [...counts]
      .map(([cwe, count]) => ({ cwe, count }))
      .sort((a, b) => b.count - a.count || a.cwe.localeCompare(b.cwe))
    return { slices: all.slice(0, MAX_ROWS), hidden: Math.max(0, all.length - MAX_ROWS) }
  }, [report])

  if (slices.length === 0) {
    return (
      <ChartCard title="漏洞类型分布">
        <ChartEmpty>
          {report.classifier_checkpoint
            ? '这次扫描没有命中函数，也就没有类别可分类'
            : '这份报告没有跑分类模型，拿不到 CWE 类别'}
        </ChartEmpty>
      </ChartCard>
    )
  }

  const total = slices.reduce((s, x) => s + x.count, 0)
  const max = Math.max(...slices.map((s) => s.count))
  const labelW = Math.max(120, Math.min(190, width * 0.42))
  const countW = 34
  const barW = Math.max(40, width - labelW - countW - 6)

  return (
    <ChartCard
      title="漏洞类型分布"
      subtitle={
        <>
          只统计<b>检测命中</b>的函数（分类器只对这些跑）· 共 {total} 个
          {hidden > 0 && `　·　另有 ${hidden} 类未显示`}
        </>
      }
    >
      <div ref={ref} style={tipHostStyle} onMouseLeave={onMouseLeave}>
        {width > 0 && (
          <svg
            width={width}
            height={slices.length * ROW_H + 4}
            role="img"
            aria-label={`漏洞类型分布，共 ${slices.length} 类`}
            onMouseLeave={onMouseLeave}
          >
            <line
              x1={labelW}
              x2={labelW}
              y1={0}
              y2={slices.length * ROW_H}
              stroke={CHART.axis}
              strokeWidth={1}
              shapeRendering="crispEdges"
            />

            {slices.map((s, i) => {
              // 条长按**组内最大值**归一化，不按绝对计数 ——
              // 小样本下按总数归一化会全是短条，看不出相对关系。
              const w = (s.count / max) * barW
              const y = i * ROW_H + (ROW_H - BAR_H) / 2
              const name = cweName(s.cwe)
              const known = s.cwe in CWE_NAMES

              return (
                <g key={s.cwe}>
                  <rect
                    x={0}
                    y={i * ROW_H}
                    width={width}
                    height={ROW_H}
                    fill="transparent"
                    onMouseMove={(e) => {
                      const box =
                        e.currentTarget.ownerSVGElement!.getBoundingClientRect()
                      setTip({
                        x: e.clientX - box.left,
                        y: e.clientY - box.top,
                        node: (
                          <>
                            <div style={{ color: '#fff' }}>{s.cwe}</div>
                            <div style={{ color: '#c9d2d8' }}>
                              {name ?? '（中文名未收录，显示原始编号）'}
                            </div>
                            <div style={{ color: '#c9d2d8' }}>
                              {s.count} 个函数 · 占 {((s.count / total) * 100).toFixed(0)}%
                            </div>
                          </>
                        ),
                      })
                    }}
                  />

                  <text
                    x={labelW - 10}
                    y={i * ROW_H + ROW_H / 2 + 3.5}
                    textAnchor="end"
                    fontSize={11}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  >
                    <tspan fill={CHART.ink}>{s.cwe}</tspan>
                    {/* 中文名用文字色；查不到的类别只显示编号，不猜 */}
                    {known && (
                      <tspan fill={CHART.muted} fontSize={10.5}>
                        {' '}
                        {name}
                      </tspan>
                    )}
                  </text>

                  <path
                    d={barPath(labelW, y, w, BAR_H)}
                    fill={CHART.accent}
                    pointerEvents="none"
                  />

                  <text
                    x={width - 2}
                    y={i * ROW_H + ROW_H / 2 + 3.5}
                    textAnchor="end"
                    fontSize={11}
                    fill="var(--ink-2)"
                    style={{ fontVariantNumeric: 'tabular-nums' }}
                  >
                    {s.count}
                  </text>
                </g>
              )
            })}
          </svg>
        )}
        <ChartTip tip={tip} width={width} />
      </div>
    </ChartCard>
  )
}
