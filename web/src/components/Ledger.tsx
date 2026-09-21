import type { ScanReport } from '../types'

/**
 * 扫描账本 —— 这次扫描的四个数字。
 *
 * 刻意**不用卡片**。四张带图标的圆角卡片是这个场景下最模板化的答案，
 * 而且卡片会把数字彼此隔开，看的人得一个个读。
 * 这里把它们摆成一行、用竖线分隔、数字用等宽字体右对齐 ——
 * 读起来像一张化验单，扫一眼就能横向比较。
 *
 * 命中数在大于 0 时用命中色，其余一律用墨色：**只有需要你注意的数字才带颜色**。
 */
export function Ledger({ report }: { report: ScanReport }) {
  const s = report.summary
  const detected = report.checkpoint !== null
  const classified = report.classifier_checkpoint !== null

  const cells: { value: string; label: string; tone?: 'flag' | 'ok' | 'mute'; hint?: string }[] = [
    { value: String(s.files_scanned), label: '文件', tone: 'mute' },
    { value: String(s.functions_total), label: '受检函数', tone: 'mute' },
    detected
      ? {
          value: String(s.functions_suspicious),
          label: '命中',
          tone: s.functions_suspicious > 0 ? 'flag' : 'ok',
          hint: s.functions_total
            ? `占全部函数的 ${((s.functions_suspicious / s.functions_total) * 100).toFixed(1)}%`
            : undefined,
        }
      : { value: '—', label: '命中', tone: 'mute', hint: '未跑检测模型' },
    classified
      ? { value: String(s.functions_classified), label: '已分类', tone: 'mute', hint: '命中函数里拿到 CWE 的' }
      : { value: '—', label: '已分类', tone: 'mute', hint: '未跑分类模型' },
  ]

  const langs = Object.entries(s.languages).sort((a, b) => b[1] - a[1])

  return (
    <section
      style={{
        background: 'var(--surface)',
        borderBottom: '1px solid var(--rule)',
        display: 'flex',
        alignItems: 'stretch',
        flexWrap: 'wrap',
      }}
    >
      {cells.map((c, i) => (
        <div
          key={c.label}
          style={{
            padding: '13px 22px 14px',
            borderLeft: i === 0 ? 'none' : '1px solid var(--rule-soft)',
            minWidth: 118,
          }}
        >
          <div
            className="mono"
            style={{
              fontSize: 27,
              lineHeight: 1.05,
              fontWeight: 500,
              letterSpacing: '-0.03em',
              color:
                c.tone === 'flag'
                  ? 'var(--flag)'
                  : c.tone === 'ok'
                    ? 'var(--ok)'
                    : 'var(--ink)',
            }}
          >
            {c.value}
          </div>
          <div className="eyebrow" style={{ marginTop: 3 }}>
            {c.label}
          </div>
          {c.hint && (
            <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginTop: 2 }}>{c.hint}</div>
          )}
        </div>
      ))}

      {/* 语言分布：不做图表，一条细比例条就够 —— 这个项目通常只有一种语言 */}
      {langs.length > 0 && (
        <div style={{ padding: '13px 22px 14px', borderLeft: '1px solid var(--rule-soft)', flex: 1, minWidth: 180 }}>
          <div style={{ display: 'flex', height: 4, borderRadius: 2, overflow: 'hidden', marginTop: 6 }}>
            {langs.map(([lang, n], i) => (
              <div
                key={lang}
                title={`${lang} · ${n} 个函数`}
                style={{
                  flex: n,
                  background: ['#0f1418', '#5a6570', '#949ea6', '#c8cfcc'][i % 4],
                }}
              />
            ))}
          </div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--ink-2)', marginTop: 7 }}>
            {langs.map(([lang, n], i) => (
              <span key={lang}>
                {i > 0 && <span style={{ color: 'var(--ink-3)', margin: '0 7px' }}>·</span>}
                {lang} <span style={{ color: 'var(--ink-3)' }}>{n}</span>
              </span>
            ))}
          </div>
          <div className="eyebrow" style={{ marginTop: 3 }}>
            语言 · 按函数数
          </div>
        </div>
      )}
    </section>
  )
}
