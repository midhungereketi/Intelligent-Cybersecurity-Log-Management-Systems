import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Backend the dev server proxies to. Override with API_TARGET when port 8000 is taken,
// e.g. API_TARGET=http://127.0.0.1:8001 npm run dev
const apiTarget = process.env.API_TARGET || 'http://127.0.0.1:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/health': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
