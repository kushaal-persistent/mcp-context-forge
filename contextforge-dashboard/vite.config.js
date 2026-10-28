import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// The gateway only allows CORS from localhost / localhost:4444 by default, so the
// dev server proxies /gateway-api/* to the gateway. No gateway configuration change
// is needed. Override the target with VITE_GATEWAY_URL (see .env.example).
//
// The Demo page (alerting walkthrough) talks to a separate, isolated demo gateway:
//   /demo-gw/*  -> http://127.0.0.1:4445  (demo gateway, alerting enabled, own database)
//   /demo-ctl/* -> http://127.0.0.1:4446  (tiny local controller, see .sasva/demo/controller.cjs)
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const target = env.VITE_GATEWAY_URL || 'http://localhost:4444';
  const demoGw = env.VITE_DEMO_GATEWAY_URL || 'http://127.0.0.1:4445';
  const demoCtl = env.VITE_DEMO_CONTROLLER_URL || 'http://127.0.0.1:4446';
  const proxy = {
    '/gateway-api': {
      target,
      changeOrigin: true,
      rewrite: (p) => p.replace(/^\/gateway-api/, ''),
    },
    '/demo-gw': {
      target: demoGw,
      changeOrigin: true,
      rewrite: (p) => p.replace(/^\/demo-gw/, ''),
    },
    '/demo-ctl': {
      target: demoCtl,
      changeOrigin: true,
      rewrite: (p) => p.replace(/^\/demo-ctl/, ''),
    },
  };
  return {
    plugins: [react()],
    server: { port: 5173, proxy },
    preview: { port: 5173, proxy },
  };
});
