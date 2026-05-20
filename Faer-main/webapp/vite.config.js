import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/safebrowsing': {
        target: 'https://safebrowsing.googleapis.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/safebrowsing/, '')
      },
      '/api/openphish': {
        target: 'https://openphish.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/openphish/, '')
      }
    }
  }
})
