// Utilities
import { defineConfig } from 'vite';
import { fileURLToPath, URL } from 'node:url';
import path from 'node:path';

// https://vitejs.dev/config/
export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
    extensions: [
      '.js',
      '.json',
      '.mjs',
      '.ts',
    ],
  },
  define: {
    'process.env': {}, // Replicate from main config, Vite handles NODE_ENV for lib mode
  },
  publicDir: false, // Disable copying of public directory
  build: {
    outDir: 'dist_auth_service/',
    lib: {
      entry: path.resolve(__dirname, 'src/components/AuthService.ts'),
      name: 'goEmployeJwtAuthService', // Global variable name for UMD build
      fileName: (format) => `auth-service.${format}.js`,
      formats: ['umd', 'es'],
    },
    rollupOptions: {
      // Externalize peer dependencies or dependencies you don't want to bundle
      external: [], // We want axios and other local deps bundled
      output: {
        // Provide global variables to use in the UMD build
        // for externalized deps, if any. Not needed if not externalizing.
        globals: {},
      },
    },
    // Ensure TypeScript files are processed
    // This is usually handled by Vite's default plugins,
    // but good to be mindful of if issues arise.
    // No specific TypeScript plugin needed here as Vite handles .ts out of the box.
  },
  // We don't need Vue or Vuetify plugins for this specific library,
  // as AuthService.ts is plain TypeScript.
  plugins: [],
});
