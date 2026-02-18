import { defineConfig, type PluginOption } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ] as PluginOption[], // Explicitly cast to PluginOption array
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})