import React, { useMemo, useState } from 'react';
import { useSession } from '../session.jsx';
import { Badge, Drawer, Empty, ErrorBox, JsonView, Spinner, useAsync, fmtDate, fmtNum, fmtMs, fmtPct } from '../components/ui.jsx';

// Fields that may carry credentials; never render them, even though the API masks most of them.
const SENSITIVE = /(auth_value|auth_token|auth_password|auth_header_value|auth_headers|client_key|client_cert|ca_certificate|oauth_config|secret|password|token|headers)/i;

function redact(value, depth = 0) {
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE.test(k) && v != null && v !== '' && !(Array.isArray(v) && v.length === 0)) out[k] = '[redacted]';
      else out[k] = redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

const tagLabels = (tags) => (tags || []).map((t) => (typeof t === 'string' ? t : t.label || t.id || JSON.stringify(t)));

const TABS = [
  {
    id: 'servers',
    label: 'Servers',
    load: (api) => api.servers(),
    text: (s) => [s.name, s.description, s.id],
    columns: [
      { h: 'Name', r: (s) => <span className="font-medium text-white">{s.name}</span> },
      { h: 'Status', r: (s) => <Status on={s.enabled} /> },
      { h: 'Tools', r: (s) => (s.associated_tools || []).length },
      { h: 'Resources', r: (s) => (s.associated_resources || []).length },
      { h: 'Prompts', r: (s) => (s.associated_prompts || []).length },
    ],
  },
  {
    id: 'gateways',
    label: 'Gateways',
    load: (api) => api.gateways(),
    text: (g) => [g.name, g.url, g.description, g.slug],
    columns: [
      { h: 'Name', r: (g) => <span className="font-medium text-white">{g.name}</span> },
      { h: 'URL', r: (g) => <span className="font-mono text-xs text-slate-400">{g.url}</span> },
      { h: 'Transport', r: (g) => g.transport || '-' },
      { h: 'Status', r: (g) => <Status on={g.enabled} reachable={g.reachable} /> },
      { h: 'Tools', r: (g) => g.tool_count ?? '-' },
      { h: 'Last seen', r: (g) => fmtDate(g.last_seen) },
    ],
  },
  {
    id: 'tools',
    label: 'Tools',
    load: (api) => api.tools(),
    text: (t) => [t.name, t.displayName, t.description, t.gateway_slug, t.integration_type],
    columns: [
      { h: 'Name', r: (t) => <span className="font-medium text-white">{t.displayName || t.name}</span> },
      { h: 'Source', r: (t) => t.gateway_slug || t.integration_type || '-' },
      { h: 'Type', r: (t) => `${t.integration_type || ''} ${t.request_type || ''}`.trim() || '-' },
      { h: 'Status', r: (t) => <Status on={t.enabled} reachable={t.reachable} /> },
      { h: 'Calls', r: (t) => fmtNum(t.metrics ? t.metrics.totalExecutions ?? t.metrics.total_executions : t.execution_count) },
    ],
    action: 'invoke',
  },
  {
    id: 'resources',
    label: 'Resources',
    load: (api) => api.resources(),
    text: (r) => [r.name, r.uri, r.description, r.mime_type],
    columns: [
      { h: 'Name', r: (r) => <span className="font-medium text-white">{r.name}</span> },
      { h: 'URI', r: (r) => <span className="font-mono text-xs text-slate-400">{r.uri}</span> },
      { h: 'MIME', r: (r) => r.mime_type || '-' },
      { h: 'Status', r: (r) => <Status on={r.enabled} /> },
    ],
  },
  {
    id: 'prompts',
    label: 'Prompts',
    load: (api) => api.prompts(),
    text: (p) => [p.name, p.display_name, p.description],
    columns: [
      { h: 'Name', r: (p) => <span className="font-medium text-white">{p.display_name || p.name}</span> },
      { h: 'Arguments', r: (p) => (p.arguments || []).map((a) => a.name).join(', ') || '-' },
      { h: 'Status', r: (p) => <Status on={p.enabled} /> },
    ],
  },
];

function Status({ on, reachable }) {
  if (on === false) return <Badge tone="slate">disabled</Badge>;
  if (reachable === false) return <Badge tone="amber">unreachable</Badge>;
  return <Badge tone="green">active</Badge>;
}

export default function Registry({ onInvoke }) {
  const { api } = useSession();
  const [tabId, setTabId] = useState('tools');
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState(null);
  const tab = TABS.find((t) => t.id === tabId);

  const { loading, data, error, reload } = useAsync(() => tab.load(api), [api, tabId]);

  const rows = useMemo(() => {
    if (!data) return [];
    const needle = q.trim().toLowerCase();
    if (!needle) return data;
    return data.filter((row) => tab.text(row).some((s) => s && String(s).toLowerCase().includes(needle)));
  }, [data, q, tab]);

  const switchTab = (id) => {
    setTabId(id);
    setQ('');
    setSelected(null);
  };

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Registry</h2>
          <p className="text-sm text-slate-400">Browse everything the gateway has registered or federated.</p>
        </div>
        <button className="btn-ghost" onClick={reload}>Refresh</button>
      </header>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-1 rounded-lg border border-ink-700 bg-ink-900 p-1" role="tablist">
          {TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={t.id === tabId}
              onClick={() => switchTab(t.id)}
              className={`rounded-md px-3 py-1.5 text-sm transition ${t.id === tabId ? 'bg-brand-500 text-white' : 'text-slate-300 hover:bg-ink-800'}`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <input className="input max-w-xs" placeholder={`Search ${tab.label.toLowerCase()}...`} value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search" />
      </div>

      {error && <ErrorBox error={error} onRetry={reload} />}

      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-6"><Spinner label={`Loading ${tab.label.toLowerCase()}...`} /></div>
        ) : rows.length === 0 ? (
          <Empty
            title={data && data.length ? 'No matches' : `No ${tab.label.toLowerCase()} registered`}
            hint={data && data.length ? 'Try a different search term.' : 'Register a peer gateway or virtual server in ContextForge and it will show up here.'}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-ink-700 bg-ink-800/50">
                <tr>
                  {tab.columns.map((c) => <th key={c.h} className="th">{c.h}</th>)}
                  {tab.action && <th className="th" />}
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {rows.map((row) => (
                  <tr key={row.id || row.uri || row.name} className="cursor-pointer hover:bg-ink-800/60" onClick={() => setSelected(row)}>
                    {tab.columns.map((c) => <td key={c.h} className="td">{c.r(row)}</td>)}
                    {tab.action === 'invoke' && (
                      <td className="td text-right">
                        <button
                          className="btn-ghost !py-1"
                          disabled={row.enabled === false}
                          onClick={(e) => {
                            e.stopPropagation();
                            onInvoke(row);
                          }}
                        >
                          Invoke
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!loading && rows.length > 0 && (
          <div className="border-t border-ink-700 px-4 py-2 text-xs text-slate-500">
            {rows.length}{data && rows.length !== data.length ? ` of ${data.length}` : ''} {tab.label.toLowerCase()}
          </div>
        )}
      </div>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title={selected ? selected.displayName || selected.display_name || selected.name : ''}>
        {selected && <Detail item={selected} kind={tabId} onInvoke={onInvoke} />}
      </Drawer>
    </div>
  );
}

function Detail({ item, kind, onInvoke }) {
  const metrics = item.metrics;
  const tags = tagLabels(item.tags);
  return (
    <div className="space-y-5">
      {item.description && <p className="text-sm text-slate-300">{item.description}</p>}
      <div className="flex flex-wrap gap-1.5">
        <Status on={item.enabled} reachable={item.reachable} />
        {tags.map((t) => <Badge key={t} tone="blue">{t}</Badge>)}
        {item.visibility && <Badge>{item.visibility}</Badge>}
      </div>

      {metrics && (metrics.totalExecutions ?? metrics.total_executions) != null && (
        <dl className="grid grid-cols-2 gap-3 text-sm">
          {[
            ['Executions', fmtNum(metrics.totalExecutions ?? metrics.total_executions)],
            ['Failure rate', fmtPct(metrics.failureRate ?? metrics.failure_rate)],
            ['Avg response', fmtMs(metrics.avgResponseTime ?? metrics.avg_response_time)],
            ['Last run', fmtDate(metrics.lastExecutionTime ?? metrics.last_execution_time)],
          ].map(([k, v]) => (
            <div key={k} className="rounded-lg border border-ink-700 p-3">
              <dt className="text-xs text-slate-500">{k}</dt>
              <dd className="font-mono text-slate-200">{v}</dd>
            </div>
          ))}
        </dl>
      )}

      {kind === 'tools' && (
        <>
          <button className="btn-primary" disabled={item.enabled === false} onClick={() => onInvoke(item)}>Open in Tool Invoker</button>
          <div>
            <div className="label">Input schema</div>
            <JsonView value={item.input_schema || {}} />
          </div>
        </>
      )}
      {kind === 'prompts' && item.template && (
        <div>
          <div className="label">Template</div>
          <JsonView value={item.template} maxHeight="max-h-64" />
        </div>
      )}

      <div>
        <div className="label">Raw record (credentials redacted)</div>
        <JsonView value={redact(item)} />
      </div>
    </div>
  );
}
