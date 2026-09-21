import type { ScanReport } from '../types'
import type { FileRow } from '../rows'
import { fixed, num, pct } from '../format'

/**
 * 概览：一个 Hero 数字 + 一行 KPI。
 *
 * 仪表盘领读的只能是**一个**数字，这里选的是「有几个函数疑似有漏洞」——
 * 它直接回答了用户点「开始检测」时想问的那句话。
 *
 * Hero 用**比例字形**（默认），不用 `tabular-nums`：等宽数字会让大字号的
 * `121` 看起来很松垮。`tabular-nums` 只留给需要纵向对齐的地方（KPI 行、表格列）。
 */
export function Overview({
  report,
  rows,
}: {
  report: ScanReport
  rows: FileRow[]
}) {
  const s = report.summary
  const detected = report.checkpoint !== null
  const classified = report.classifier_checkpoint !== null

  // 只统计**这一轮扫过**的文件。刚添加、还没进模型的那些在侧栏显示为「待检测」，
  // 不参与这里的任何比率 —— 否则"命中率"的分母会把没扫过的文件也算进去。
  const scanned = rows.filter((r) => r.state !== 'pending')
  const pendingCount = rows.length - scanned.length
  const hitFiles = scanned.filter((r) => r.state === 'hit').length
  const withFns = scanned.filter((r) => (r.file?.function_count ?? 0) > 0).length
  const rate = s.functions_total
    ? s.functions_suspicious / s.functions_total
    : 0

  const kpis: { value: string; label: string; tone?: 'flag' | 'ok' | 'mute'; hint?: string }[] = [
    {
      value: num(s.files_scanned),
      label: '文件',
      tone: 'mute',
      hint: pendingCount > 0 ? `另有 ${pendingCount} 个待检测` : undefined,
    },
    // 没跑检测时必须是「—」而不是「0 / 7」：后者写的是"一个都没命中"，
    // 而事实是"根本没检测过"。绿色的 0/N 尤其误导。
    detected
      ? {
          value: `${hitFiles} / ${withFns}`,
          label: '有命中的文件',
          tone: hitFiles > 0 ? 'flag' : 'ok',
        }
      : { value: '—', label: '有命中的文件', tone: 'mute', hint: '未跑检测模型' },
    { value: num(s.functions_total), label: '受检函数', tone: 'mute' },
    classified
      ? {
          value: num(s.functions_classified),
          label: '已分类',
          tone: 'mute',
          hint: '命中函数里拿到 CWE 的',
        }
      : { value: '—', label: '已分类', tone: 'mute', hint: '未跑分类模型' },
    detected && report.threshold !== null
      ? {
          value: fixed(report.threshold, 2),
          label: '判定阈值',
          tone: 'mute',
          hint: 'F1 调优，偏召回的代价是误报',
        }
      : { value: '—', label: '判定阈值', tone: 'mute', hint: '未跑检测模型' },
  ]

  return (
    <section
      className="panel"
      style={{
        display: 'flex',
        alignItems: 'stretch',
        flexWrap: 'wrap',
        overflow: 'hidden',
      }}
    >
      {/* ---- Hero ---- */}
      <div style={{ padding: '16px 26px 15px', minWidth: 250 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 9 }}>
          <span
            style={{
              fontSize: 52,
              lineHeight: 1,
              fontWeight: 600,
              letterSpacing: '-0.045em',
              color: detected && s.functions_suspicious > 0 ? 'var(--flag)' : 'var(--ink)',
            }}
          >
            {detected ? num(s.functions_suspicious) : '—'}
          </span>
          <span style={{ fontSize: 14, color: 'var(--ink-2)' }}>个函数</span>
        </div>
        <div
          style={{
            marginTop: 6,
            fontSize: 12.5,
            color: 'var(--ink-2)',
            lineHeight: 1.5,
          }}
        >
          {detected ? (
            <>
              疑似存在漏洞，占受检的 <b>{pct(rate)}</b>
              <div style={{ fontSize: 11, color: 'var(--ink-3)', marginTop: 2 }}>
                注意：阈值是按 F1 调的，判为有漏洞≠一定有漏洞
              </div>
            </>
          ) : (
            '这份报告没有跑检测模型'
          )}
        </div>
      </div>

      {/* ---- KPI 行 ---- */}
      {kpis.map((k, i) => (
        <div
          key={k.label}
          style={{
            padding: '16px 20px 15px',
            borderLeft: '1px solid var(--rule-soft)',
            minWidth: 122,
            flex: i === 1 ? '0 1 auto' : '0 1 auto',
          }}
        >
          <div
            className="mono"
            style={{
              fontSize: 21,
              lineHeight: 1.1,
              fontWeight: 500,
              letterSpacing: '-0.02em',
              // 只有需要你注意的数字才带颜色
              color:
                k.tone === 'flag'
                  ? 'var(--flag)'
                  : k.tone === 'ok'
                    ? 'var(--ok)'
                    : 'var(--ink)',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {k.value}
          </div>
          <div className="eyebrow" style={{ marginTop: 4 }}>
            {k.label}
          </div>
          {k.hint && (
            <div style={{ fontSize: 10.5, color: 'var(--ink-3)', marginTop: 2 }}>{k.hint}</div>
          )}
        </div>
      ))}
    </section>
  )
}
