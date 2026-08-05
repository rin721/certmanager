import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
	rolldownOptions: {
	  output: {
		codeSplitting: {
		  groups: [
			{ name: 'react-vendor', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
			{ name: 'mui-icons', test: /node_modules[\\/]@mui[\\/]icons-material[\\/]/ },
			{ name: 'mui-core', test: /node_modules[\\/]@mui[\\/]/ },
			{ name: 'emotion', test: /node_modules[\\/]@emotion[\\/]/ },
			{ name: 'query-router', test: /node_modules[\\/](@tanstack|react-router|react-router-dom)[\\/]/ },
			{ name: 'forms', test: /node_modules[\\/](react-hook-form|zod|@hookform)[\\/]/ },
		  ],
		},
	  },
	},
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
      '/readyz': 'http://127.0.0.1:8080',
    },
  },
})
