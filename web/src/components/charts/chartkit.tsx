/**
 * 图表的公共零件与设计令牌。
 *
 * 为什么颜色写在 TS 里而不是 `index.css`：图表是 SVG，色阶要做**插值**
 * （`mixRamp` 得拿到具体色值算），CSS 变量在运行时取不到可用于计算的数字。
 * 所以这里是图表配色的唯一真相源；页面其余部分的颜色仍走 `index.css`。
 *
 * 这些色值不是挑出来的，是**跑校验器验出来的**
 * （`dataviz/scripts/validate_palette.js`，白底 #ffffff）：
 *
 *   命中 #b02a1f ↔ 安全 #0e8f5a —— CVD ΔE 8.3（≥8）、常视 ΔE 28.4、
 *   对比度 ≥3:1、色度 ≥0.1，全项 PASS。
 *
 * ⚠️ 项目原有的 `--ok: #2e6b52` **在图表里不能用** —— 校验器判它色度 0.076
 * 低于 0.1 下限（「读起来发灰」）。界面文字仍用 `--ok`，图表用这里的 `ok`。
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

/* ------------------------------------------------------------------ 令牌 */

export const CHART = {
  /** 命中 / 有漏洞 —— 状态色，不是"第 1 个系列" */
  flag: '#b02a1f',
  /** 安全 / 未命中 */
  ok: '#0e8f5a',
  /** 单系列计数的强调色（名义类别用单色，不用彩虹） */
  accent: '#1f4fd8',
  /** 网格线：比表面深一档的发丝线，实线（虚线会被误读成阈值） */
  grid: '#e6eae8',
  axis: '#d4dad8',
  muted: '#949ea6',
  ink: '#0f1418',
  surface: '#ffffff',
  /** 顺序色阶（单一蓝色，明度单调递增）。离散格子用，最浅档 2.11:1 达标 */
  ramp: ['#86b6ef', '#5598e7', '#2a78d6', '#1c5cab', '#104281'] as const,
  /**
   * 「没有数据」—— 报告里没跑检测时用。
   *
   * ⚠️ 这个色**必须存在**。少了它，`suspicious_count` 为 0 的文件会被画成
   * 绿色的"未命中"，于是一份**根本没跑过检测**的报告在图表上显示为
   * "全部安全" —— 把"没跑过"读成"判定为空"，正是 `types.ts` 开头警告的坑。
   * 用一个中性灰明确表示"这儿没有结论"。
   */
  nodata: '#c8cfcc',
}

/** 两根相贴的条之间的间隙，用**表面色**分隔 —— 而不是给条描边。 */
export const GAP = 2

/** 条的圆角。数据末端圆、基线端方。 */
export const R = 4

/* ------------------------------------------------------------------ 插值 */

/** 在色阶上取第 t 档（0~1）。`t` 会被夹到合法区间。 */
export function rampAt(t: number): string {
  const r = CHART.ramp
  const i = Math.max(0, Math.min(r.length - 1, Math.round(t * (r.length - 1))))
  return r[i]
}

/* -------------------------------------------------------------- 尺寸测量 */

/**
 * 量出容器的实际像素宽。
 *
 * 为什么不直接用 `viewBox` + `width="100%"` 缩放：那会把**文字也一起缩放**，
 * 容器一窄字就小到读不了。这里按真实像素画，文字永远保持正常字号。
 */
export function useMeasure<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(0)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => {
      setWidth(Math.floor(entry.contentRect.width))
    })
    ro.observe(el)
    setWidth(Math.floor(el.getBoundingClientRect().width))
    return () => ro.disconnect()
  }, [])

  return [ref, width] as const
}

/* ---------------------------------------------------------------- 图形件 */

/** 末端圆角、基线端方角的横向条。 */
export function barPath(x: number, y: number, w: number, h: number, r = R): string {
  if (w <= 0) return ''
  const rr = Math.min(r, w, h / 2)
  return [
    `M ${x} ${y}`,
    `H ${x + w - rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + w} ${y + rr}`,
    `V ${y + h - rr}`,
    `A ${rr} ${rr} 0 0 1 ${x + w - rr} ${y + h}`,
    `H ${x}`,
    'Z',
  ].join(' ')
}

/** 图表卡片外壳。标题走 `.eyebrow`，副标题给"该怎么读这张图"。 */
export function ChartCard({
  title,
  subtitle,
  right,
  children,
}: {
  title: string
  subtitle?: ReactNode
  right?: ReactNode
  children: ReactNode
}) {
  return (
    <section
      className="panel"
      style={{
        padding: '13px 16px 14px',
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
      }}
    >
      <header
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 10,
          flexWrap: 'wrap',
        }}
      >
        <span className="eyebrow">{title}</span>
        <span style={{ flex: 1 }} />
        {right}
      </header>
      {subtitle && (
        <div
          style={{
            fontSize: 11,
            color: 'var(--ink-3)',
            marginTop: 3,
            lineHeight: 1.45,
          }}
        >
          {subtitle}
        </div>
      )}
      <div style={{ marginTop: 10, flex: 1, minWidth: 0 }}>{children}</div>
    </section>
  )
}

/** 图例。**≥2 个系列时必须出现** —— 别让读的人靠颜色去猜身份。 */
export function Legend({
  items,
}: {
  items: { color: string; label: string }[]
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
      {items.map((it) => (
        <span
          key={it.label}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
        >
          <span
            aria-hidden
            style={{
              width: 9,
              height: 9,
              borderRadius: 2,
              background: it.color,
              flexShrink: 0,
            }}
          />
          {/* 文字用文字色，**不穿数据色** —— 浅色系列当文字根本读不清 */}
          <span style={{ fontSize: 11, color: 'var(--ink-2)' }}>{it.label}</span>
        </span>
      ))}
    </div>
  )
}

/** 图表里的占位说明（没有数据时）。 */
export function ChartEmpty({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        height: 120,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 12,
        color: 'var(--ink-3)',
        textAlign: 'center',
        padding: '0 12px',
      }}
    >
      {children}
    </div>
  )
}

/* ---------------------------------------------------------------- 悬浮层 */

export interface TipState {
  x: number
  y: number
  node: ReactNode
}

/**
 * 图表的悬浮读数状态。
 *
 * **移入显示容易，移出消失容易漏 —— 漏了弹窗就会一直挂在页面上。**
 * 所以这里把「清掉」这件事做成必须显式挂上去的东西，而不是各图自己记得写：
 * 返回的 `onMouseLeave` 要挂在**外层容器**和 `<svg>` 两处 ——
 * 只挂 svg 时，鼠标移到卡片标题上（还在容器里）弹窗不会消失。
 */
export function useChartTip() {
  const [tip, setTip] = useState<TipState | null>(null)
  const clear = useCallback(() => setTip(null), [])
  return { tip, setTip, onMouseLeave: clear }
}

/**
 * 跟随鼠标的读数气泡。
 *
 * 定位用 `pointer-events: none` 的绝对定位层，靠 `transform` 平移，
 * 不做逐帧 React 重渲染 —— 图表里的鼠标移动很密，重渲染会卡。
 *
 * 注意：**它是增强，不是唯一读数途径**。每张图都另有直接标注和坐标轴刻度，
 * 不能让人"必须悬停才能知道数值"。
 */
export function ChartTip({
  tip,
  width,
}: {
  tip: TipState | null
  width: number
}) {
  if (!tip || width === 0) return null
  // 靠右时翻到左侧，避免气泡被容器裁掉
  const flip = tip.x > width - 150
  return (
    <div
      aria-hidden
      // 给自动化验证一个抓手：断言"鼠标移开之后页面上没有气泡了"
      data-chart-tip=""
      style={{
        position: 'absolute',
        left: 0,
        top: 0,
        transform: `translate(${tip.x}px, ${tip.y}px)`,
        pointerEvents: 'none',
        zIndex: 5,
      }}
    >
      <div
        style={{
          transform: `translate(${flip ? 'calc(-100% - 12px)' : '12px'}, -50%)`,
          background: 'var(--ink)',
          color: '#fff',
          borderRadius: 3,
          padding: '6px 9px',
          fontSize: 11,
          lineHeight: 1.5,
          whiteSpace: 'nowrap',
          fontFamily: 'var(--font-mono)',
          boxShadow: '0 2px 10px rgba(15,20,24,0.22)',
        }}
      >
        {tip.node}
      </div>
    </div>
  )
}

/** 悬浮层要挂在 `position: relative` 的容器上。 */
export const tipHostStyle = { position: 'relative' as const }
