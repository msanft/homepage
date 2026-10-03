import { preview } from 'vite';

// Serve exactly the Pages artifact, without SvelteKit's SSR preview fallback.
await preview({
  configFile: false,
  appType: 'mpa',
  build: { outDir: 'build' },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true }
});
