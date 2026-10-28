import React, { useMemo, useRef, useState } from 'react';
import { useSession } from '../session.jsx';
import { Badge, ErrorBox, Spinner, Stat, useAsync, fmtMs, fmtNum, fmtPct, fmtDate } from '../components/ui.jsx';
import { BarList, Sparkline } from '../components/charts.jsx';

const REFRESH_MS = 10000;
const ENTITIES = [
  ['tools', 'Tools'],
  ['resources', 'Resources'],
  ['prompts', 'Prompts'],
  ['servers', 'Servers'],
];

const toolMetric = (t) => {
  const m = t.metrics || {};
  return {
    total: m.totalExecutions ?? m.total_executions ?? t.execution_count ?? 0,
    failed: m.failedExecutions ?? m.failed_executions ?? 0,
    rate: m.failureRate ?? m.failure_rate ?? 0,
    avg: m.avgResponseTime ?? m.avg_response_time ?? null,
    max: m.maxResponseTime ?? m.max_response_time ?? null,
    last: m.lastExecutionTime ?? m.last_execution_time ?? null,
  };
};

export default function Metrics() {
  const { api } = useSession();
  const trend = useRef([]);
  const [sort, setSort] = useState('total');

  const { loading, data, error, reload, at } = useAsync(
    async () => {
      const [metrics, tools] = await Promise.all([api.metrics(), api.tools().catch(() => [])]);
      trend.current = [...trend.current, metrics.tools.totalExecutions].slice(-30);
      return { metrics, tools };
    },
    [api],
    { pollMs: REFRESH_MS }
  );

  const rows = useMemo(() => {
    if (!data) return [];
    const r = data.tools.map((t) => ({ t, m: toolMetric(t) }));
    const key = { total: (x) => x.m.total, rate: (x) => x.m.rate, avg: (x) => x.m.avg ?? -1 }[sort];
    return r.sort((a, b) => key(b) - key(a));
  }, [data, sort]);

  if (loading && !data) return <Spinner label="Loading metrics..." />;
  if (error && !data) return <ErrorBox error={error} onRetry={reload} />;

  const { metrics } = data;
  const a2a = metrics.a2aAgents;
  const top = rows.filter((r) => r.m.total > 0).slice(0, 8);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Metrics</h2>
          <p className="text-sm text-slate-400">
            Execution counts and latency reported by the gateway.
            {at && <span className="ml-2 text-xs text-slate-500">updated {at.toLocaleTimeString()} (auto-refresh {REFRESH_MS / 1000}s)</span>}
          </p>
        </div>
        <button className="btn-ghost" onClick={reload}>Refresh</button>
      </header>

      {error && <ErrorBox error={error} onRetry={reload} />}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {ENTITIES.map(([k, label]) => {
          const m = metrics[k];
          return (
            <div key={k} className="card p-4">
              <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
              <div className="mt-1 text-2xl font-semibold text-white">{fmtNum(m.totalExecutions)}</div>
              <dl className="mt-3 space-y-1 text-xs">
                <div className="flex justify-between"><dt className="text-slate-500">Success</dt><dd className="font-mono text-emerald-300">{fmtNum(m.successfulExecutions)}</dd></div>
                <div className="flex justify-between"><dt className="text-slate-500">Failed</dt><dd className={`font-mono ${m.failedExecutions ? 'text-rose-300' : 'text-slate-300'}`}>{fmtNum(m.failedExecutions)}</dd></div>
                <div className="flex justify-between"><dt className="text-slate-500">Failure rate</dt><dd className="font-mono text-slate-300">{fmtPct(m.failureRate)}</dd></div>
                <div className="flex justify-between"><dt className="text-slate-500">Avg / max</dt><dd className="font-mono text-slate-300">{fmtMs(m.avgResponseTime)} / {fmtMs(m.maxResponseTime)}</dd></div>
              </dl>
            </div>
          );
        })}
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="card p-5 lg:col-span-2">
          <h3 className="mb-4 text-sm font-semibold text-white">Busiest tools</h3>
          <BarList data={top.map((r) => ({ label: r.t.displayName || r.t.name, value: r.m.total, color: r.m.failed ? '#fbbf24' : '#5b7fff' }))} format={fmtNum} empty="No tool executions recorded yet. Run a tool from the Invoker." />
        </div>
        <div className="card p-5">
          <h3 className="mb-1 text-sm font-semibold text-white">Tool executions (live)</h3>
          <p className="mb-3 text-xs text-slate-500">Total sampled every {REFRESH_MS / 1000}s while this page is open.</p>
          <Sparkline points={trend.current} />
          <div className="mt-3 text-xs text-slate-400">Last execution: {fmtDate(metrics.tools.lastExecutionTime)}</div>
        </div>
      </section>

      {a2a && (
        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Stat label="A2A agents" value={`${a2a.activeAgents}/${a2a.totalAgents}`} sub="active / total" />
          <Stat label="A2A interactions" value={fmtNum(a2a.totalInteractions)} />
          <Stat label="A2A success rate" value={`${Number(a2a.successRate).toFixed(1)}%`} />
          <Stat label="A2A avg response" value={fmtMs(a2a.avgResponseTime)} />
        </section>
      )}

      <section className="card overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-700 px-4 py-3">
          <h3 className="text-sm font-semibold text-white">Per-tool statistics</h3>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            Sort by
            <select className="input !w-auto !py-1" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort tools">
              <option value="total">Executions</option>
              <option value="rate">Failure rate</option>
              <option value="avg">Avg latency</option>
            </select>
          </div>
        </div>
        {rows.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">No tools registered.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-ink-700 bg-ink-800/50">
                <tr>{['Tool', 'Status', 'Executions', 'Failed', 'Failure rate', 'Avg', 'Max', 'Last run'].map((h) => <th key={h} className="th">{h}</th>)}</tr>
              </thead>
              <tbody className="divide-y divide-ink-800">
                {rows.map(({ t, m }) => (
                  <tr key={t.id}>
                    <td className="td font-medium text-white">{t.displayName || t.name}</td>
                    <td className="td">{t.enabled === false ? <Badge>disabled</Badge> : t.reachable === false ? <Badge tone="amber">unreachable</Badge> : <Badge tone="green">active</Badge>}</td>
                    <td className="td font-mono">{fmtNum(m.total)}</td>
                    <td className={`td font-mono ${m.failed ? 'text-rose-300' : ''}`}>{fmtNum(m.failed)}</td>
                    <td className="td font-mono">{fmtPct(m.rate)}</td>
                    <td className="td font-mono">{fmtMs(m.avg)}</td>
                    <td className="td font-mono">{fmtMs(m.max)}</td>
                    <td className="td text-xs text-slate-400">{fmtDate(m.last)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
