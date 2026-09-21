import { useMemo } from 'react'

import type { FileRow } from '../../rows'
import {
  CHART,
  ChartCard,
  ChartEmpty,
  ChartTip,
  GAP,
  Legend,
  barPath,
  tipHostStyle,
  useChartTip,
  useMeasure,
} from './chartkit'

/**
 * 文件风险排行：每个文件的「命中 / 未命中」占比。
 *
 * 为什么是**横向**：文件名很长（`add_push_report_sideband_pkt.c` 这种），
 * 竖着放标签只能斜着写或截断，两个都难读。
 *
 * 为什么是**堆叠**而不是单一长度的条：光看命中数会漏掉重要信息 ——
 * 「5 个里中 5 个」和「50 个里中 5 个」危险程度差着量级。
 * 堆叠条同时给出分子和分母，占比一眼可见。
 *
 * 配色用的是**状态色**（红=有漏洞、绿=安全），不是两个"系列色" ——
 * 这里的颜色真的在表达好/坏，属于状态语义。
 */
const ROW_H = 24
const BAR_H = 14

export function FileRiskRanking({
  rows,
  selectedId,
  onSelect,
}: {
  rows: FileRow[]
  selectedId?: string
  onSelect: (client_id: string) => void
}) {
  const [ref, width] = useMeasure<HTMLDivElement>()
  const { tip, setTip, onMouseLeave } = useChartTip()

  // 一个函数都没抽到的文件不参与排行 —— 它没有分子也没有分母。
  // 这类文件仍然在左列的清单里（带「无函数」徽标），不会被藏掉。
  const ranked = useMemo(
    () =>
      rows
        .filter((r) => r.file && r.file.function_count > 0)
        .sort((a, b) => {
          const d = b.file!.suspicious_count - a.file!.suspicious_count
          if (d !== 0) return d
          // 命中数相同时，占比高的排前面，再相同按路径稳定排序
          const ra = a.file!.suspicious_count / a.file!.function_count
          const rb = b.file!.suspicious_count / b.file!.function_count
          if (rb !== ra) return rb - ra
          return a.displayName.localeCompare(b.displayName)
        }),
    [rows],
  )

  if (ranked.length === 0) {
    return (
      <ChartCard title="文件风险排行">
        <ChartEmpty>还没有可排行的文件</ChartEmpty>
      </ChartCard>
    )
  }

  const labelW = Math.max(76, Math.min(170, width * 0.3))
  const countW = 54
  const barW = Math.max(40, width - labelW - countW - 6)
  const hitFiles = ranked.filter((r) => r.state === 'hit').length
  // 报告里有没有跑过检测。没跑过时这一整张图都是"没有结论"，
  // 绝不能画成一片绿 —— 那等于宣称"全部安全"。
  const anyDetected = ranked.some((r) => r.state !== 'undetected')

  return (
    <ChartCard
      title="文件风险排行"
      subtitle={
        anyDetected ? (
          <>
            条长 = 该文件的函数总数，红色段 = 其中判定为有漏洞的
            {'　·　'}
            <b style={{ color: 'var(--flag)' }}>{hitFiles}</b> / {ranked.length} 个文件有命中
          </>
        ) : (
          <>这份报告没有跑检测模型，这里只能给出每个文件的函数数</>
        )
      }
      right={
        anyDetected ? (
          <Legend
            items={[
              { color: CHART.flag, label: '命中' },
              { color: CHART.ok, label: '未命中' },
            ]}
          />
        ) : (
          <Legend items={[{ color: CHART.nodata, label: '未检测' }]} />
        )
      }
    >
      <div ref={ref} style={tipHostStyle} onMouseLeave={onMouseLeave}>
        {width > 0 && (
          <svg
            width={width}
            height={ranked.length * ROW_H + 4}
            role="img"
            aria-label="按文件的漏洞命中排行"
            onMouseLeave={onMouseLeave}
          >
            {/* 基线：条从这里长出去 */}
            <line
              x1={labelW}
              x2={labelW}
              y1={0}
              y2={ranked.length * ROW_H}
              stroke={CHART.axis}
              strokeWidth={1}
              shapeRendering="crispEdges"
            />

            {ranked.map((row, i) => {
              const fr = row.file!
              const total = fr.function_count
              const hits = fr.suspicious_count
              const cleans = total - hits
              const on = row.client_id === selectedId
              // 没跑过检测：整条画成中性灰，不参与"命中/未命中"的二分
              const unknown = row.state === 'undetected'

              // 两段合起来必须正好占满 barW：先把 gap 从总量里扣掉再按比例分
              const usable = hits > 0 && cleans > 0 ? barW - GAP : barW
              const wHit = (hits / total) * usable
              const wClean = (cleans / total) * usable

              const y = i * ROW_H + (ROW_H - BAR_H) / 2

              return (
                <g key={row.client_id}>
                  <rect
                    x={0}
                    y={i * ROW_H}
                    width={width}
                    height={ROW_H}
                    fill={on ? '#f4f7fb' : 'transparent'}
                    style={{ cursor: 'pointer' }}
                    onClick={() => onSelect(row.client_id)}
                    onMouseMove={(e) => {
                      const box =
                        e.currentTarget.ownerSVGElement!.getBoundingClientRect()
                      setTip({
                        x: e.clientX - box.left,
                        y: e.clientY - box.top,
                        node: (
                          <>
                            <div style={{ color: '#fff' }}>{row.displayName}</div>
                            {unknown ? (
                              <>
                                <div style={{ color: '#c9d2d8' }}>
                                  共 {total} 个函数
                                </div>
                                <div style={{ color: '#c9d2d8' }}>
                                  这份报告没跑检测，没有结论
                                </div>
                              </>
                            ) : (
                              <>
                                <div style={{ color: '#f0a39b' }}>命中 {hits}</div>
                                <div style={{ color: '#7fd3ac' }}>未命中 {cleans}</div>
                                <div style={{ color: '#c9d2d8' }}>
                                  共 {total} 个函数 · 命中率{' '}
                                  {((hits / total) * 100).toFixed(0)}%
                                </div>
                              </>
                            )}
                          </>
                        ),
                      })
                    }}
                  />

                  <text
                    x={labelW - 10}
                    y={i * ROW_H + ROW_H / 2 + 3.5}
                    textAnchor="end"
                    fontSize={12}
                    fill={on ? 'var(--ink)' : 'var(--ink-2)'}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  >
                    {clip(row.displayName, labelW - 16)}
                  </text>

                  {unknown ? (
                    /* 没跑检测：一条中性灰的通条，"有多少函数"仍然可见，
                       但**不表达任何安全判断** */
                    <path
                      d={barPath(labelW, y, barW, BAR_H)}
                      fill={CHART.nodata}
                      pointerEvents="none"
                    />
                  ) : (
                    <>
                      {/* 未命中段（贴基线，方角） */}
                      {cleans > 0 && (
                        <rect
                          x={labelW}
                          y={y}
                          width={wClean}
                          height={BAR_H}
                          fill={CHART.ok}
                          pointerEvents="none"
                        />
                      )}
                      {/* 命中段（数据末端，圆角） */}
                      {hits > 0 && (
                        <path
                          d={barPath(labelW + wClean + (cleans > 0 ? GAP : 0), y, wHit, BAR_H)}
                          fill={CHART.flag}
                          pointerEvents="none"
                        />
                      )}
                    </>
                  )}

                  {/* 数值放在固定列里右对齐 —— 贴在条尾会被长短不一的条搞得参差不齐 */}
                  <text
                    x={width - 2}
                    y={i * ROW_H + ROW_H / 2 + 3.5}
                    textAnchor="end"
                    fontSize={11}
                    fill={unknown ? 'var(--ink-3)' : hits > 0 ? CHART.flag : 'var(--ink-3)'}
                    style={{ fontVariantNumeric: 'tabular-nums' }}
                  >
                    {unknown ? `${total} 个` : `${hits}/${total}`}
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

/**
 * 按**字符数**粗略截断长文件名。
 *
 * 用字符数而不是测量像素宽度：标签是等宽字体，每字符宽度固定，
 * 按字体大小估算足够准，而且不用在渲染前测量 DOM。
 */
function clip(s: string, maxPx: number): string {
  const per = 7.2 // 等宽 12px 的单字符宽度，实测值
  const max = Math.max(6, Math.floor(maxPx / per))
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}
