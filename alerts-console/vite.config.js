import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Dev/preview only: the SPA calls the gateway at VITE_API_BASE (default "/api"), and
// this proxy forwards /api/* to VITE_GATEWAY_URL. In production the same /api prefix is
// served by a reverse proxy (see nginx.conf.template), so the browser never needs CORS.
//
// Default target is the isolated demo gateway (port 4445), which has alerting enabled.
// Point VITE_GATEWAY_URL at your real gateway once ALERTING_ENABLED=true there.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const target = env.VITE_GATEWAY_URL || 'http://127.0.0.1:4445';
  const proxy = {
    '/api': {
      target,
      changeOrigin: true,
      rewrite: (p) => p.replace(/^\/api/, ''),
    },
  };
  return {
    plugins: [react()],
    server: { port: 5174, proxy },
    preview: { port: 5174, proxy },
  };
});
