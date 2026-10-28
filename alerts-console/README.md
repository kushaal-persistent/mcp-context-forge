# ContextForge Alerts Console

A standalone web app for the gateway's alerting API (`/v1/alerts`, issue #5805). Users sign in with
their gateway email and password, see alerts update live, and acknowledge, resolve and filter them.

## What it does today

- Sign in with gateway email and password (`POST /v1/auth/email/login`); sign out revokes the token.
- Inbox: filters (status, severity, source, unread), paging, detail drawer, acknowledge, resolve, bulk actions.
- Live updates over Server-Sent Events with automatic reconnect and `Last-Event-ID` replay. Toasts and an unread badge.
- Preferences: per-user rules (global or per source, in-app or webhook, minimum severity).

## What it does not do

- **Webhook and email delivery.** The gateway only delivers in-app today (`mcpgateway/services/alert_delivery.py`).
  The Preferences page can save webhook rules, but nothing is sent until the backend adds that adapter.
- **Admin screens** (channels, defaults, status) are not built.
- **Team scoping** is whatever the gateway enforces; the app never sends a team id.

## Run it (development)

```
npm install --include=dev      # --include=dev matters if NODE_ENV=production is set
npm run dev                    # http://127.0.0.1:5174
npm test                       # unit tests (Node's built-in runner)
```

The dev server proxies `/api/*` to `VITE_GATEWAY_URL` (default `http://127.0.0.1:4445`, the isolated demo
gateway with alerting on). Copy `.env.example` to `.env` to change it. The gateway must run with
`ALERTING_ENABLED=true`, otherwise `/v1/alerts` returns 404 and the app says so.

## Deploy

`Dockerfile` builds the app and serves it with nginx (`nginx.conf.template`), which forwards `/api/*` to the
gateway (`GATEWAY_UPSTREAM`). Same origin means no gateway CORS settings. **These two files have not been built or
run yet.** Serve the app over HTTPS in production.

## Security notes

- The token is kept in `sessionStorage` (cleared when the tab closes), not `localStorage`.
  A httpOnly cookie would be safer, but the gateway returns the token in the response body.
- After sign-out the gateway still accepts the old token for up to about 30 seconds
  (`AUTH_CACHE_REVOCATION_TTL`, default 30). Verified on the demo gateway: 200 at 1.5s, 401 at 35s.
- Accounts with a forced password change get a clear message from the gateway; change it in the gateway Admin UI first.
- Alert text and details are rendered as plain text, never as HTML.

## Layout

```
src/lib/      api client, SSE client, formatting helpers (unit tested)
src/pages/    Login, Inbox, Preferences
src/session.jsx, src/live.jsx   session and the single shared live stream
```
