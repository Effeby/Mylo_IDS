import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['mylo-ids.site', 'www.mylo-ids.site', 'localhost', '173.212.241.228'],
    host: '0.0.0.0',
    port: 5173
  }
})
