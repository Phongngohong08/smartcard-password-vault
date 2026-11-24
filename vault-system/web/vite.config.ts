import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Khi phát triển: web chạy ở :5173, mọi request /api được chuyển tới Vault server :8080.
// Card Agent (:8765) được gọi trực tiếp từ trình duyệt (agent tự cho phép origin này).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { '/api': 'http://127.0.0.1:8080' },
  },
})
