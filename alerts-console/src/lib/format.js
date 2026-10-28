// Shared constants and pure helpers (no React, no DOM) so they can be unit tested.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
export const STATUSES = ['open', 'acknowledged', 'resolved', 'expired', 'suppressed'];
// Matches ALERT_SOURCES in mcpgateway/services/metrics.py
export const SOURCES = ['security', 'gateway_health', 'performance', 'a2a', 'plugin'];

const SEVERITY_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
export const severityRank = (s) => SEVERITY_RANK[s] ?? -1;

// The API returns datetimes that may carry no timezone suffix (naive UTC). JavaScript
// would read those as local time and show wrong "x minutes ago" values, so treat a
// timestamp without an offset as UTC.
export function parseUtc(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  const s = String(value);
  const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
  const d = new Date(hasZone ? s : s + 'Z');
  return Number.isNaN(d.getTime()) ? null : d;
}

export function relativeTime(value, now = Date.now()) {
  const d = parseUtc(value);
  if (!d) return '-';
  const sec = Math.round((now - d.getTime()) / 1000);
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h ago`;
  return `${Math.round(hr / 24)}d ago`;
}

export function absoluteTime(value) {
  const d = parseUtc(value);
  return d ? d.toLocaleString() : '-';
}

// Which lifecycle actions make sense for an alert in a given status.
export function allowedActions(alert) {
  const open = alert.status === 'open';
  const acked = alert.status === 'acknowledged';
  return { ack: open, resolve: open || acked };
}

// Build the query string for GET /v1/alerts. Empty filters are dropped.
export function buildListQuery({ status, severity, source, unread, page = 1, pageSize = 25 } = {}) {
  const qs = new URLSearchParams();
  if (status) qs.set('status', status);
  if (severity) qs.set('severity', severity);
  if (source) qs.set('source', source);
  if (unread) qs.set('unread', 'true');
  qs.set('page', String(page));
  qs.set('page_size', String(pageSize));
  return qs.toString();
}

// Turn a FastAPI error body into one readable line.
export function describeError(status, body) {
  const detail = body && typeof body === 'object' ? body.detail : body;
  let text = '';
  if (typeof detail === 'string') text = detail;
  else if (Array.isArray(detail)) {
    text = detail.map((d) => (d && d.msg ? `${(d.loc || []).slice(1).join('.')}: ${d.msg}` : JSON.stringify(d))).join('; ');
  } else if (detail) text = JSON.stringify(detail);
  if (body && typeof body === 'object' && body.hint) text = `${text} ${body.hint}`.trim();
  if (status === 403 && !text) text = 'You do not have permission to do that.';
  return text || `Request failed (${status})`;
}
