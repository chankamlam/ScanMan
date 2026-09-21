import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // 前端上传扫描时发 /api/* 请求，这里转发到本地 Flask 后端（scripts/serve.py）。
    // 这样前端代码里始终写相对路径 /api/scan，不用区分开发/生产。
    // 改后端端口（scripts/serve.py --port）时这里的 target 要同步改。
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
