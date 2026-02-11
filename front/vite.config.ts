import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/status/dashboard/',
  server: {
    proxy: {
      '/status/format/json': {
        target: 'http://localhost:80',
        changeOrigin: true,
      },
    },
  },
})
