# ContextForge Dashboard

A standalone React + Vite + Tailwind client for a running [ContextForge](../README.md) gateway.
It talks to the gateway's REST API with a JWT bearer token.

## Features

- **Overview** - health / readiness, version, uptime, database and Redis status, registry counts, tool availability, host CPU and memory (auto-refresh every 15s).
- **Registry** - browse Servers, Gateways, Tools, Resources and Prompts with search and a detail drawer. Credential-like fields are redacted in the raw record view.
- **Tool Invoker** - pick a tool, fill a form generated from its JSON Schema (or switch to raw JSON), run it via JSON-RPC `tools/call`, and see the result, latency and error state. Keeps the last 15 calls with replay.
- **Metrics** - per-entity execution counts, failure rate and latency, busiest tools, A2A agent stats and a sortable per-tool table (auto-refresh every 10s).

## Run it

Requires Node 18+.

```bash
cd contextforge-dashboard
npm install --include=dev   # --include=dev matters if NODE_ENV=production is set in your shell
npm run dev                 # http://localhost:5173
```

Open the app and paste a JWT. Generate one from the repo root, using the same `JWT_SECRET_KEY` the gateway runs with:

```bash
python -m mcpgateway.utils.create_jwt_token \
  --username admin@example.com --exp 10080 --secret "$JWT_SECRET_KEY"
```

If the gateway's Python environment is not available, any HS256 JWT with `iss=mcpgateway`, `aud=mcpgateway-api`, a `sub` of an existing admin user, and (when `ENVIRONMENT` is set) a matching `env` claim will work.

## How it connects

The gateway only allows CORS from `http://localhost` and `http://localhost:4444` by default, so a browser app on another port cannot call it directly. The dev server therefore **proxies `/gateway-api/*` to the gateway** (see `vite.config.js`), which needs no gateway changes. The proxy target defaults to `http://localhost:4444`; override it:

```bash
# .env
VITE_GATEWAY_URL=http://my-gateway:4444
```

The "Gateway API base URL" field on the connect screen defaults to `/gateway-api`. You can instead enter a direct URL (e.g. `http://localhost:4444`) if you add this app's origin to the gateway's `ALLOWED_ORIGINS`.

`npm run build` produces a static `dist/`. `npm run preview` serves it with the same proxy. If you host `dist/` elsewhere, put a reverse proxy in front that forwards to the gateway, or configure `ALLOWED_ORIGINS`.

## Security notes

- The token is stored in the browser's `localStorage` and sent only to the configured base URL. Use "Disconnect" to clear it.
- Prefer short-lived tokens. This app does not mint or refresh tokens.
- The Tool Invoker runs real tools with the token's permissions. Treat it like an admin console.

## Project layout

```
src/
  api.js                 gateway client (auth, list normalisation, tools/call)
  session.jsx            connection state + localStorage
  App.jsx                shell, hash routing, session resume
  pages/                 Overview, Registry, Invoker, Metrics
  components/            ui helpers, SVG charts, JSON-Schema form, connect screen
```

## Notes and limitations

- List endpoints are fetched with `limit=0` (all) and cursors are followed up to 20 pages.
- The schema form handles flat objects (string, number, integer, boolean, enum). Nested objects and arrays use a JSON text box. `oneOf`/`anyOf`/`$ref` schemas fall back to JSON for the unsupported parts.
- Metrics are whatever `/metrics` and each tool record report; there is no historical time series beyond the live in-page sample.
