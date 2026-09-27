import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    // This forces Vite to translate the legacy 'require' syntax in these libraries
    include: ['react-simple-maps', 'react-tooltip', 'prop-types']
  }
})