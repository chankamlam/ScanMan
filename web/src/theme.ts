import type { ThemeConfig } from 'antd'

/**
 * Ant Design 的主题令牌。
 *
 * 目的：让 antd 组件（表格、抽屉、标签）服从 `index.css` 里那套设计令牌，
 * 而不是各自带着库的默认皮肤 —— 默认皮肤正是"看起来像模板"的来源。
 *
 * 这里只放**能被令牌表达**的部分；更细的覆盖（表头字距、行分隔线）在
 * `index.css` 里用选择器做，因为 antd 的令牌覆盖不到那些属性。
 */
export const theme: ThemeConfig = {
  token: {
    // 主色只用在一个地方：可交互的强调（链接、选中、焦点）
    colorPrimary: '#1f4fd8',
    colorLink: '#1f4fd8',

    colorText: '#0f1418',
    colorTextSecondary: '#5a6570',
    colorTextTertiary: '#949ea6',
    colorBorder: '#d4dad8',
    colorBorderSecondary: '#e6eae8',
    colorBgContainer: '#ffffff',
    colorBgLayout: '#eef0ef',

    fontFamily: "'Archivo Variable', system-ui, -apple-system, 'Segoe UI', sans-serif",
    fontSize: 14,

    // 圆角压到最小：这是仪器读数，不是气泡界面
    borderRadius: 3,
    borderRadiusLG: 3,
    borderRadiusSM: 2,

    // 阴影几乎不用 —— 层次靠细线和留白建立
    boxShadow: 'none',
    boxShadowSecondary: 'none',
  },
  components: {
    Table: {
      headerBg: '#f7f8f7',
      headerSplitColor: 'transparent',
      rowHoverBg: '#f4f7fb',
      cellPaddingBlockSM: 7,
      cellPaddingInlineSM: 12,
    },
    Tag: {
      defaultBg: '#f0f2f1',
      defaultColor: '#5a6570',
      borderRadiusSM: 2,
    },
    Card: {
      paddingLG: 18,
    },
    Tooltip: {
      colorBgSpotlight: '#0f1418',
      borderRadius: 3,
    },
  },
}
