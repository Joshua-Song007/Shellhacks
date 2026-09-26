import { resolve } from 'node:path';
import { defineConfig } from 'vite';

// base './' so the built files load over file:// inside Electron.
export default defineConfig({
  base: './',
  build: { rollupOptions: { input: { main: resolve('index.html'), genome: resolve('genome.html') } } },
});
