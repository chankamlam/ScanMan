import { useMemo, useState } from 'react'
import { Empty, List, Table, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import type { FileResult, FunctionInfo } from '../types'

/**
 * 文件清单。
 *
 * 保留表格（它就该是表格 —— 这是清单，不是导航），但把每一列的字形和
 * 对齐方式按内容定：路径用等宽、数字右对齐、判定用小色块。
 *
 * 表的顺序默认按**命中数降序**：一屏之内最该被看到的排在最上面。
 */
export function FileTable({
  files,
  selected,
  onSelect,
}: {
  files: FileResult[]
  selected: { file: string; fn: FunctionInfo } | null
  onSelect: (file: string, fn: FunctionInfo) => void
}) {
  // 默认隐藏「一个函数都没抽到」的文件：C 项目里 .h 只有声明，
  // 全列出来会让表里一半是空行，把真正有问题的挤下去。
  const [hideEmpty, setHideEmpty] = useState(true)

  const shown = useMemo(
    () => (hideEmpty ? files.filter((f) => f.function_count > 0) : files),
    [files, hideEmpty],
  )
  const hidden = files.length - shown.length

  const columns: ColumnsType<FileResult> = [
    {
      title: '文件',
      dataIndex: 'path',
      key: 'path',
      render: (path: string, row) => (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <span className="mono" style={{ fontSize: 13 }}>
            {path}
          </span>
          {!row.parse_ok && (
            <Tooltip title="语法树里有错误节点，抽取结果可能不完整">
              <span
                className="mono"
                style={{
                  fontSize: 10,
                  padding: '0 5px',
                  borderRadius: 2,
                  background: '#fdf3e3',
                  color: 'var(--warn)',
                }}
              >
                解析异常
              </span>
            </Tooltip>
          )}
        </span>
      ),
      sorter: (a, b) => a.path.localeCompare(b.path),
    },
    {
      title: '语言',
      dataIndex: 'language',
      key: 'language',
      width: 92,
      filters: [...new Set(files.map((f) => f.language ?? 'unknown'))].map((l) => ({
        text: l,
        value: l,
      })),
      onFilter: (v, row) => (row.language ?? 'unknown') === v,
      render: (l: string | null) => (
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-2)' }}>
          {l ?? '—'}
        </span>
      ),
    },
    {
      title: '函数',
      dataIndex: 'function_count',
      key: 'function_count',
      width: 74,
      align: 'right',
      sorter: (a, b) => a.function_count - b.function_count,
      render: (n: number) => <span className="mono" style={{ fontSize: 12 }}>{n}</span>,
    },
    {
      title: '命中',
      dataIndex: 'suspicious_count',
      key: 'suspicious_count',
      width: 92,
      align: 'right',
      defaultSortOrder: 'descend',
      sorter: (a, b) => a.suspicious_count - b.suspicious_count,
      render: (n: number, row) =>
        n > 0 ? (
          <span
            className="mono"
            style={{ fontSize: 15, fontWeight: 500, color: 'var(--flag)', letterSpacing: '-0.02em' }}
          >
            {n}
          </span>
        ) : (
          <span className="mono" style={{ fontSize: 11, color: row.function_count > 0 ? 'var(--ok)' : 'var(--ink-3)' }}>
            {row.function_count > 0 ? '干净' : '—'}
          </span>
        ),
    },
    {
      title: '路径占比',
      key: 'ratio',
      width: 130,
      sorter: (a, b) =>
        b.suspicious_count / Math.max(b.function_count, 1) -
        a.suspicious_count / Math.max(a.function_count, 1),
      render: (_, row) => {
        const p = row.function_count ? row.suspicious_count / row.function_count : 0
        return (
          <span style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span style={{ flex: 1, height: 4, background: 'var(--rule-soft)', borderRadius: 2, overflow: 'hidden', minWidth: 40 }}>
              <span
                style={{
                  display: 'block',
                  width: `${p * 100}%`,
                  height: '100%',
                  background: p > 0 ? 'var(--flag)' : 'var(--ok)',
                }}
              />
            </span>
            <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)', width: 34, textAlign: 'right' }}>
              {(p * 100).toFixed(0)}%
            </span>
          </span>
        )
      },
    },
  ]

  return (
    <section className="panel">
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: '11px 16px',
          borderBottom: '1px solid var(--rule)',
        }}
      >
        <span className="eyebrow">文件清单</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          {shown.length} 个
          {hidden > 0 && ` · 另有 ${hidden} 个无函数已隐藏`}
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
            checked={hideEmpty}
            onChange={(e) => setHideEmpty(e.target.checked)}
            style={{ accentColor: 'var(--signal)', margin: 0 }}
          />
          隐藏无函数的文件
        </label>
      </div>

      <Table<FileResult>
        rowKey="path"
        columns={columns}
        dataSource={shown}
        size="small"
        pagination={shown.length > 25 ? { pageSize: 25, size: 'small' } : false}
        expandable={{
          rowExpandable: (row) => row.functions.length > 0,
          expandedRowRender: (row) => (
            <FunctionList
              file={row}
              selected={selected?.file === row.path ? selected.fn : null}
              onSelect={(fn) => onSelect(row.path, fn)}
            />
          ),
        }}
      />
    </section>
  )
}

/** 一个文件里的函数。命中的排前面，其余按行号。 */
function FunctionList({
  file,
  selected,
  onSelect,
}: {
  file: FileResult
  selected: FunctionInfo | null
  onSelect: (fn: FunctionInfo) => void
}) {
  if (file.functions.length === 0) {
    return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有抽到函数" />
  }

  const sorted = [...file.functions].sort((a, b) => {
    const av = a.verdict === 'vulnerable' ? 0 : 1
    const bv = b.verdict === 'vulnerable' ? 0 : 1
    return av !== bv ? av - bv : a.start_line - b.start_line
  })

  return (
    <List
      size="small"
      dataSource={sorted}
      renderItem={(fn) => {
        const on = selected?.name === fn.name && selected?.start_line === fn.start_line
        const vul = fn.verdict === 'vulnerable'
        return (
          <List.Item
            onClick={() => onSelect(fn)}
            style={{
              cursor: 'pointer',
              padding: '5px 10px',
              // 选中和悬停都不换背景，只加一条左边框 —— 保持清单的克制
              borderLeft: on ? '2px solid var(--signal)' : '2px solid transparent',
              background: on ? '#f4f7fb' : undefined,
            }}
          >
            <span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 10, minWidth: 0 }}>
              <span
                className="mono"
                style={{ fontSize: 11, color: 'var(--ink-3)', width: 42, textAlign: 'right', flexShrink: 0 }}
              >
                {fn.start_line}
              </span>
              <span className="mono" style={{ fontSize: 13, color: 'var(--ink)', whiteSpace: 'nowrap' }}>
                {fn.name}
              </span>
              {'verdict' in fn && (
                <span
                  className="mono"
                  style={{
                    fontSize: 10.5,
                    padding: '0 5px',
                    borderRadius: 2,
                    flexShrink: 0,
                    background: vul ? 'var(--flag-bg)' : 'var(--ok-bg)',
                    color: vul ? 'var(--flag)' : 'var(--ok)',
                  }}
                >
                  {vul ? '有漏洞' : '安全'}
                </span>
              )}
              {'cwe' in fn && fn.cwe && (
                <Tooltip title="模型预测的漏洞类型">
                  <span
                    className="mono"
                    style={{
                      fontSize: 10.5,
                      padding: '0 5px',
                      borderRadius: 2,
                      flexShrink: 0,
                      background: '#f0f2f1',
                      color: 'var(--ink-2)',
                    }}
                  >
                    {fn.cwe}
                  </span>
                </Tooltip>
              )}
            </span>
            <span style={{ flex: 1 }} />
            {'prob_vulnerable' in fn && (
              <span
                className="mono"
                style={{
                  fontSize: 12,
                  color: 'var(--ink-3)',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {((fn.prob_vulnerable ?? 0) * 100).toFixed(1)}%
              </span>
            )}
          </List.Item>
        )
      }}
    />
  )
}
