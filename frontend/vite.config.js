import { resolve } from 'node:path';
import { defineConfig } from 'vite';

// base './' so the built files load over file:// inside Electron.
export default defineConfig({
  base: './',
  server: { watch: { ignored: ['**/release/**'] } }, // electron-builder output; writing it mid-session force-reloaded the dev app
  build: { rollupOptions: { input: { main: resolve('index.html'), genome: resolve('genome.html') } } },
});
