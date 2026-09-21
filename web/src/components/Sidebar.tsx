import { useRef } from 'react'
import { Spin, Tooltip } from 'antd'

import type { FileRow } from '../rows'
import { stateBadge } from '../rows'

/** `accept` 的值必须和 `src/extract.py` 的 `LANGUAGE_BY_EXT` 对齐。 */
const ACCEPT = [
  '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx',
  '.py', '.pyw', '.pyi',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.php', '.php3', '.php5', '.phtml',
].join(',')

/**
 * 左列：这一页的「工程」—— 用户挑了哪些文件，以及什么时候开始检测。
 *
 * 列表里**一个文件都不隐藏**。老界面有个「隐藏无函数的文件」开关，
 * 那是因为它扫的是整棵目录树、`.h` 会占掉半屏；
 * 这里的文件是用户自己一个个挑的，藏掉任何一个都会让人以为选丢了。
 * 抽不出函数的显示「无函数」，抽取失败的显示「抽取失败」和原因。
 */
export function Sidebar({
  rows,
  selectedId,
  onSelect,
  onAddFiles,
  onRemove,
  onScan,
  onClear,
  scanning,
  scanHint,
}: {
  rows: FileRow[]
  selectedId: string | null
  onSelect: (client_id: string) => void
  onAddFiles: (files: FileList) => void
  onRemove: (client_id: string) => void
  onScan: () => void
  onClear: () => void
  scanning: boolean
  /** 「开始检测」不能点时的原因，直接显示给用户 */
  scanHint: string | null
}) {
  const inputRef = useRef<HTMLInputElement>(null)

  return (
    <aside
      style={{
        width: 272,
        flexShrink: 0,
        borderRight: '1px solid var(--rule)',
        background: 'var(--surface)',
        display: 'flex',
        flexDirection: 'column',
        minHeight: 0,
      }}
    >
      {/* ---- 标题栏 ---- */}
      <div
        style={{
          padding: '12px 14px 10px',
          borderBottom: '1px solid var(--rule-soft)',
          display: 'flex',
          alignItems: 'baseline',
          gap: 8,
        }}
      >
        <span className="eyebrow">文件</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--ink-3)' }}>
          {rows.length} 个
        </span>
        <span style={{ flex: 1 }} />
        {rows.length > 0 && (
          <button onClick={onClear} className="linkish" style={{ fontSize: 11 }}>
            清空
          </button>
        )}
      </div>

      {/* ---- 文件清单 ---- */}
      <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
        {rows.length === 0 ? (
          <div
            style={{
              padding: '28px 16px',
              textAlign: 'center',
              fontSize: 12,
              color: 'var(--ink-3)',
              lineHeight: 1.7,
            }}
          >
            还没有文件
            <br />
            点下面的按钮添加
          </div>
        ) : (
          rows.map((row) => (
            <FileRowItem
              key={row.client_id}
              row={row}
              on={row.client_id === selectedId}
              onClick={() => onSelect(row.client_id)}
              onRemove={() => onRemove(row.client_id)}
            />
          ))
        )}
      </div>

      {/* ---- 操作区 ---- */}
      <div
        style={{
          padding: 12,
          borderTop: '1px solid var(--rule)',
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          accept={ACCEPT}
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files?.length) onAddFiles(e.target.files)
            // 清空 value，否则连续选同一个文件不会触发 change
            e.target.value = ''
          }}
        />
        <button className="btn btn-ghost" onClick={() => inputRef.current?.click()}>
          + 添加文件
        </button>

        <button
          className="btn btn-primary"
          onClick={onScan}
          disabled={scanning || !!scanHint}
          title={scanHint ?? undefined}
        >
          {scanning ? <Spin size="small" /> : null}
          {scanning ? '检测中…' : '开始检测'}
        </button>

        {scanHint && (
          <div
            style={{
              fontSize: 11,
              color: 'var(--ink-3)',
              lineHeight: 1.5,
              textAlign: 'center',
            }}
          >
            {scanHint}
          </div>
        )}
      </div>
    </aside>
  )
}

/** 一行文件：名字 + 状态徽标（+ 解析异常警告）。 */
function FileRowItem({
  row,
  on,
  onClick,
  onRemove,
}: {
  row: FileRow
  on: boolean
  onClick: () => void
  onRemove: () => void
}) {
  const badge = stateBadge(row)
  // parse_ok=false 的文件**照样能抽出函数** —— 它在每张图里都长得完全正常，
  // 但 span 是可疑的。这个警告得留在看得见的地方。
  const parseWarn = row.file && !row.file.parse_ok

  return (
    <div
      onClick={onClick}
      className="file-row"
      style={{
        padding: '8px 12px 8px 14px',
        cursor: 'pointer',
        background: on ? '#f4f7fb' : undefined,
        // 选中只加一条左边框，不换整块底色 —— 保持清单的克制
        borderLeft: on ? '2px solid var(--signal)' : '2px solid transparent',
        borderBottom: '1px solid var(--rule-soft)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
        <span
          className="mono"
          style={{
            fontSize: 12.5,
            color: 'var(--ink)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            flex: 1,
            minWidth: 0,
          }}
          title={row.displayName}
        >
          {row.displayName}
        </span>

        {parseWarn && (
          <Tooltip title="语法树里有错误节点，抽取到的函数范围可能不完整">
            <span
              className="mono"
              style={{
                fontSize: 10,
                color: 'var(--warn)',
                background: '#fdf3e3',
                borderRadius: 2,
                padding: '0 4px',
                flexShrink: 0,
              }}
            >
              ⚠
            </span>
          </Tooltip>
        )}

        <button
          className="row-x"
          title="移除"
          onClick={(e) => {
            e.stopPropagation()
            onRemove()
          }}
        >
          ×
        </button>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
        {badge && (
          <span
            className="mono"
            style={{
              fontSize: 10.5,
              padding: '1px 6px',
              borderRadius: 2,
              color: badge.color,
              background: badge.bg,
              fontWeight: 500,
            }}
          >
            {badge.label}
          </span>
        )}
        {row.reason && (
          <Tooltip title={row.reason}>
            <span
              className="mono"
              style={{
                fontSize: 10,
                color: 'var(--ink-3)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                minWidth: 0,
              }}
            >
              {row.reason.split(':')[0]}
            </span>
          </Tooltip>
        )}
      </div>
    </div>
  )
}
