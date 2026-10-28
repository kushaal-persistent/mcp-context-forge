import { buildListQuery, describeError } from './format.js';

export class ApiError extends Error {
  constructor(message, status, body) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

/**
 * Client for the ContextForge alerts API.
 *  - base:           URL prefix the browser uses ("/api" by default, forwarded to the gateway)
 *  - getToken:       returns the current bearer token (or null)
 *  - onUnauthorized: called once when an authenticated request gets 401 (token expired/revoked)
 */
export function createApi({ base, getToken, onUnauthorized = () => {} }) {
  const root = base.replace(/\/+$/, '');

  async function request(path, { method = 'GET', body, signal, auth = true } = {}) {
    const headers = { Accept: 'application/json' };
    const token = auth ? getToken() : null;
    if (token) headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    let res;
    try {
      res = await fetch(root + path, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal,
      });
    } catch (e) {
      if (e.name === 'AbortError') throw e;
      throw new ApiError('Cannot reach the gateway. Check your connection and try again.', 0);
    }

    const text = await res.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = text; }
    }
    if (!res.ok) {
      if (res.status === 401 && auth) onUnauthorized();
      throw new ApiError(describeError(res.status, data), res.status, data);
    }
    return data;
  }

  return {
    streamUrl: `${root}/v1/alerts/stream`,

    login: (email, password) =>
      request('/v1/auth/email/login', { method: 'POST', body: { email, password }, auth: false }),

    listAlerts: (filters, signal) => request(`/v1/alerts?${buildListQuery(filters)}`, { signal }),
    unreadCount: async (signal) => {
      const r = await request(`/v1/alerts?${buildListQuery({ unread: true, page: 1, pageSize: 1 })}`, { signal });
      return r.total;
    },
    getAlert: (id, signal) => request(`/v1/alerts/${encodeURIComponent(id)}`, { signal }),
    acknowledge: (id) => request(`/v1/alerts/${encodeURIComponent(id)}/ack`, { method: 'POST', body: {} }),
    resolve: (id) => request(`/v1/alerts/${encodeURIComponent(id)}/resolve`, { method: 'POST', body: {} }),
    bulk: (action, ids) => request('/v1/alerts/bulk', { method: 'POST', body: { action, ids } }),

    getPreferences: (signal) => request('/v1/alerts/preferences', { signal }),
    savePreferences: (items) => request('/v1/alerts/preferences', { method: 'PUT', body: { items } }),

    // Needs the alerts.manage permission; other users get 403.
    adminStatus: (signal) => request('/admin/alerts/status', { signal }),
  };
}
