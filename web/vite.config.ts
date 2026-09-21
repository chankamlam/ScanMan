import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // 阶段 2 接后端时用：前端发 /api/* 的请求会被转发到 FastAPI（scripts/serve.py）
    // 这样前端代码里始终写相对路径 /api/scan，不用区分开发/生产。
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
})
