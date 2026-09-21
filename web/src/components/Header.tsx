import type { HealthInfo } from '../api'
import { shortPath } from '../format'

/**
 * 头部：项目主题大字 + 一句话说明 + 模型状态灯。
 *
 * 状态灯不是装饰 —— 「开始检测」能不能点、点了要等多久，全看模型加载到哪一步，
 * 这件事必须在页面上一直看得见，而不是等用户点了才告诉他。
 */
export function Header({ health, healthErr }: { health: HealthInfo | null; healthErr: string | null }) {
  return (
    <header
      style={{
        background: 'var(--surface)',
        borderBottom: '1px solid var(--rule)',
        padding: '18px 24px 16px',
        display: 'flex',
        alignItems: 'center',
        gap: 20,
        flexWrap: 'wrap',
      }}
    >
      <ScanMark />

      <div style={{ minWidth: 0 }}>
        {/* 主题大字：英文名 + 中文主题并排，中文降一档字重做补充 */}
        <h1
          style={{
            margin: 0,
            display: 'flex',
            alignItems: 'baseline',
            gap: 12,
            flexWrap: 'wrap',
            lineHeight: 1.1,
          }}
        >
          <span
            style={{
              fontSize: 30,
              fontWeight: 600,
              letterSpacing: '-0.035em',
              color: 'var(--ink)',
            }}
          >
            ScanMan
          </span>
          <span
            style={{
              fontSize: 22,
              fontWeight: 500,
              letterSpacing: '0.01em',
              color: 'var(--ink-2)',
            }}
          >
            代码漏洞检测
          </span>
        </h1>
        <p
          style={{
            margin: '5px 0 0',
            fontSize: 12,
            color: 'var(--ink-3)',
            lineHeight: 1.5,
          }}
        >
          用 CodeBERT 微调出的两个模型：<b>检测</b>哪个函数有漏洞，
          <b>分类</b>它是哪一类 CWE
        </p>
      </div>

      <span style={{ flex: 1 }} />
      <ModelLight health={health} healthErr={healthErr} />
    </header>
  )
}

/** 一个被「扫描」过的方框：外面是框，里面是勾。 */
function ScanMark() {
  return (
    <svg width="34" height="34" viewBox="0 0 26 26" aria-hidden style={{ flexShrink: 0 }}>
      <rect
        x="1.5"
        y="1.5"
        width="23"
        height="23"
        rx="3"
        fill="none"
        stroke="var(--ink)"
        strokeWidth="2"
      />
      <path
        d="M7 13.5 L11.5 18 L19 8"
        fill="none"
        stroke="var(--flag)"
        strokeWidth="2.6"
        strokeLinecap="square"
      />
    </svg>
  )
}

/**
 * 模型状态灯。
 *
 * 四种情况必须分得开 —— 它们的处置方式完全不同：
 *   加载中 → 等一会儿；就绪 → 可以点；
 *   加载失败 → 要去终端看日志；连不上后端 → 是 serve.py 没起来。
 */
function ModelLight({
  health,
  healthErr,
}: {
  health: HealthInfo | null
  healthErr: string | null
}) {
  const { color, bg, label, detail } = describe(health, healthErr)

  return (
    <div
      title={health?.error ?? healthErr ?? undefined}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 9,
        padding: '7px 13px',
        background: bg,
        borderRadius: 3,
        border: '1px solid var(--rule-soft)',
        maxWidth: 380,
      }}
    >
      <span
        aria-hidden
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: color,
          flexShrink: 0,
        }}
      />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--ink)' }}>{label}</div>
        {detail && (
          <div
            className="mono"
            style={{
              fontSize: 10,
              color: 'var(--ink-3)',
              marginTop: 1,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {detail}
          </div>
        )}
      </div>
    </div>
  )
}

function describe(health: HealthInfo | null, healthErr: string | null) {
  // 用 !== null 而不是真值判断：错误消息理论上不该是空串，
  // 但只要它空了，"出错了"就会被误读成"还在连"（api.ts 里有对应的兜底）。
  if (healthErr !== null) {
    return {
      color: 'var(--flag)',
      bg: 'var(--flag-bg)',
      label: '连不上后端',
      detail: healthErr,
    }
  }
  if (!health) {
    return { color: 'var(--ink-3)', bg: 'var(--surface-2)', label: '正在连接后端…', detail: '' }
  }
  switch (health.status) {
    case 'loading':
      return {
        color: 'var(--warn)',
        bg: '#fdf3e3',
        label: '模型加载中…',
        detail: '首次加载约十几秒，请稍候',
      }
    case 'error':
      return {
        color: 'var(--flag)',
        bg: 'var(--flag-bg)',
        label: '模型加载失败',
        detail: health.error ?? '看后端终端的日志',
      }
    case 'ready':
      return {
        color: 'var(--ok)',
        bg: 'var(--ok-bg)',
        label: '模型就绪',
        detail: [
          health.device ? `设备 ${health.device}` : null,
          health.gpu,
          health.classifier ? shortPath(health.classifier) : null,
        ]
          .filter(Boolean)
          .join(' · '),
      }
  }
}
