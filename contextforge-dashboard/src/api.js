// Thin client for the ContextForge gateway REST API.
// All calls go through `base` (default "/gateway-api", proxied by Vite to the gateway).

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export const DEFAULT_BASE = '/gateway-api';

function joinUrl(base, path) {
  return base.replace(/\/+$/, '') + (path.startsWith('/') ? path : '/' + path);
}

async function request({ base, token }, path, { method = 'GET', body, signal } = {}) {
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let res;
  try {
    res = await fetch(joinUrl(base, path), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(`Cannot reach gateway at ${base} (${e.message})`, 0);
  }

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const detail =
      (data && (data.detail || data.message || (data.error && data.error.message))) ||
      (typeof data === 'string' ? data.slice(0, 200) : '') ||
      res.statusText;
    throw new ApiError(
      res.status === 401 || res.status === 403
        ? `Authentication failed (${res.status}): ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`
        : `${res.status} ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`,
      res.status,
      data
    );
  }
  return data;
}

// List endpoints return either a bare array or a cursor-paginated object such as
// { tools: [...], nextCursor }. Normalise to an array and follow cursors (bounded).
const COLLECTION_KEYS = ['tools', 'servers', 'gateways', 'resources', 'prompts', 'items', 'data'];

function extractList(data) {
  if (Array.isArray(data)) return { items: data, next: null };
  if (data && typeof data === 'object') {
    for (const k of COLLECTION_KEYS) {
      if (Array.isArray(data[k])) return { items: data[k], next: data.nextCursor || data.next_cursor || null };
    }
  }
  return { items: [], next: null };
}

async function listAll(ctx, path, extra = '') {
  const out = [];
  let cursor = null;
  for (let page = 0; page < 20; page++) {
    const qs = new URLSearchParams();
    qs.set('limit', '0');
    qs.set('include_pagination', 'true');
    if (cursor) qs.set('cursor', cursor);
    const data = await request(ctx, `${path}?${qs.toString()}${extra}`);
    const { items, next } = extractList(data);
    out.push(...items);
    if (!next) break;
    cursor = next;
  }
  return out;
}

export function createApi(ctx) {
  return {
    health: () => request(ctx, '/health'),
    ready: () => request(ctx, '/ready'),
    version: () => request(ctx, '/version'),
    metrics: () => request(ctx, '/metrics'),
    tools: () => listAll(ctx, '/tools', '&include_inactive=true'),
    servers: () => listAll(ctx, '/servers', '&include_inactive=true'),
    gateways: () => listAll(ctx, '/gateways', '&include_inactive=true'),
    resources: () => listAll(ctx, '/resources', '&include_inactive=true'),
    prompts: () => listAll(ctx, '/prompts', '&include_inactive=true'),

    // Invoke a tool through the gateway's JSON-RPC endpoint.
    // Returns { ok, result, error, raw, ms }.
    async callTool(name, args) {
      const started = performance.now();
      const raw = await request(ctx, '/rpc', {
        method: 'POST',
        body: { jsonrpc: '2.0', id: Date.now(), method: 'tools/call', params: { name, arguments: args || {} } },
      });
      const ms = Math.round(performance.now() - started);
      if (raw && raw.error) {
        return { ok: false, error: raw.error, raw, ms };
      }
      const result = raw && raw.result !== undefined ? raw.result : raw;
      return { ok: !(result && result.isError), result, raw, ms };
    },
  };
}

// Probe credentials: /health is public, so verify the token against an authenticated route.
export async function verifyConnection(ctx) {
  const health = await request({ ...ctx, token: '' }, '/health');
  await request(ctx, '/version'); // throws ApiError on 401/403
  return health;
}
