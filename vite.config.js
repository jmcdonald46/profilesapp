import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    publicDir: 'public', // Ensures public folder is copied to dist
    build: {
        outDir: 'dist',
        assetsDir: 'assets',
        copyPublicDir: true // Explicitly copy public directory
    }
})