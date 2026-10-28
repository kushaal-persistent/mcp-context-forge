import React, { useRef } from 'react';
import { useSession } from '../session.jsx';
import { Badge, Stat, ErrorBox, Spinner, useAsync, fmtNum, fmtUptime, fmtPct } from '../components/ui.jsx';
import { Donut, Sparkline } from '../components/charts.jsx';

const REFRESH_MS = 15000;

async function settle(promises) {
  const keys = Object.keys(promises);
  const res = await Promise.allSettled(Object.values(promises));
  const out = {};
  keys.forEach((k, i) => {
    out[k] = res[i].status === 'fulfilled' ? { ok: true, value: res[i].value } : { ok: false, error: res[i].reason };
  });
  return out;
}

export default function Overview({ go }) {
  const { api } = useSession();
  const history = useRef({ cpu: [], mem: [] });

  const { loading, data, error, reload, at } = useAsync(
    async () => {
      const r = await settle({
        health: api.health(),
        ready: api.ready(),
        version: api.version(),
        metrics: api.metrics(),
        tools: api.tools(),
        servers: api.servers(),
        gateways: api.gateways(),
        resources: api.resources(),
        prompts: api.prompts(),
      });
      // If every call failed the gateway is unreachable / token rejected.
      if (Object.values(r).every((x) => !x.ok)) throw Object.values(r)[0].error;
      const sys = r.version.ok && r.version.value.system;
      if (sys) {
        const h = history.current;
        h.cpu = [...h.cpu, sys.cpu_percent ?? 0].slice(-30);
        const pct = sys.mem_total_mb ? (sys.mem_used_mb / sys.mem_total_mb) * 100 : 0;
        h.mem = [...h.mem, pct].slice(-30);
      }
      return r;
    },
    [api],
    { pollMs: REFRESH_MS }
  );

  if (loading && !data) return <Spinner label="Loading gateway status..." />;
  if (error && !data) return <ErrorBox error={error} onRetry={reload} />;

  const { health, ready, version, metrics, tools, servers, gateways, resources, prompts } = data;
  const v = version.ok ? version.value : null;
  const m = metrics.ok ? metrics.value : null;
  // Redis being unreachable only matters when it is the configured cache backend.
  const redisUnused = !!v && v.settings.cache_type !== 'redis';
  const healthy = health.ok && health.value.status === 'healthy';
  const isReady = ready.ok && ready.value.status === 'ready';

  const count = (r) => (r.ok ? r.value.length : null);
  const toolList = tools.ok ? tools.value : [];
  const enabledTools = toolList.filter((t) => t.enabled).length;
  const reachableTools = toolList.filter((t) => t.reachable).length;
  const gwList = gateways.ok ? gateways.value : [];
  const gwUp = gwList.filter((g) => g.reachable !== false && g.enabled !== false).length;

  const cards = [
    { id: 'servers', label: 'Virtual servers', n: count(servers) },
    { id: 'gateways', label: 'Gateways (peers)', n: count(gateways) },
    { id: 'tools', label: 'Tools', n: count(tools) },
    { id: 'resources', label: 'Resources', n: count(resources) },
    { id: 'prompts', label: 'Prompts', n: count(prompts) },
  ];

  const totalExec = m ? m.tools.totalExecutions + m.resources.totalExecutions + m.prompts.totalExecutions + m.servers.totalExecutions : null;

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Overview</h2>
          <p className="text-sm text-slate-400">
            {v ? `${v.app.name} ${v.app.version} - MCP ${v.app.mcp_protocol_version}` : 'Gateway status'}
            {at && <span className="ml-2 text-xs text-slate-500">updated {at.toLocaleTimeString()} (auto-refresh {REFRESH_MS / 1000}s)</span>}
          </p>
        </div>
        <button className="btn-ghost" onClick={reload}>Refresh</button>
      </header>

      {error && <ErrorBox error={error} onRetry={reload} />}

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="card p-4">
          <div className="text-xs font-medium uppercase tracking-wide text-slate-400">Health</div>
          <div className="mt-2 flex items-center gap-2">
            <Badge tone={healthy ? 'green' : 'red'}>{healthy ? 'healthy' : health.ok ? health.value.status : 'unreachable'}</Badge>
            <Badge tone={isReady ? 'green' : 'amber'}>{isReady ? 'ready' : ready.ok ? ready.value.status : 'not ready'}</Badge>
          </div>
          {ready.ok && (
            <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
              {(ready.value.status_items || []).map((i) => (
                <li key={i.name}>{i.name}: {i.message}</li>
              ))}
            </ul>
          )}
        </div>
        <Stat label="Uptime" value={v ? fmtUptime(v.uptime_seconds) : '-'} sub={v ? v.host : undefined} />
        <Stat
          label="Database"
          value={v ? (v.database.reachable ? 'Connected' : 'Down') : '-'}
          tone={v ? (v.database.reachable ? 'good' : 'bad') : undefined}
          sub={v ? `${v.database.dialect} ${v.database.server_version || ''}` : undefined}
        />
        <Stat
          label="Redis"
          value={v ? (v.redis.available ? (v.redis.reachable ? 'Connected' : redisUnused ? 'Unreachable (unused)' : 'Down') : 'Not configured') : '-'}
          tone={v && v.redis.available ? (v.redis.reachable ? 'good' : redisUnused ? undefined : 'bad') : undefined}
          sub={v ? `cache backend: ${v.settings.cache_type}` : undefined}
        />
      </section>

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {cards.map((c) => (
          <button
            key={c.id}
            className="card p-4 text-left transition hover:border-brand-500"
            onClick={() => go('registry')}
            title="Open registry"
          >
            <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{c.label}</div>
            <div className="mt-1 text-2xl font-semibold text-white">{c.n == null ? '-' : fmtNum(c.n)}</div>
          </button>
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="card p-5">
          <h3 className="mb-4 text-sm font-semibold text-white">Tool availability</h3>
          <Donut
            centre={`${enabledTools}/${toolList.length}`}
            sub="enabled"
            segments={[
              { label: 'Enabled & reachable', value: toolList.filter((t) => t.enabled && t.reachable).length, color: '#34d399' },
              { label: 'Enabled, unreachable', value: toolList.filter((t) => t.enabled && !t.reachable).length, color: '#fbbf24' },
              { label: 'Disabled', value: toolList.filter((t) => !t.enabled).length, color: '#64748b' },
            ]}
          />
          <p className="mt-3 text-xs text-slate-500">{reachableTools} reachable, {gwUp}/{gwList.length} gateways up</p>
        </div>

        <div className="card p-5">
          <h3 className="mb-4 text-sm font-semibold text-white">Executions (all entity types)</h3>
          <div className="text-3xl font-semibold text-white">{totalExec == null ? '-' : fmtNum(totalExec)}</div>
          {m && (
            <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <dt className="text-slate-500">Tool failure rate</dt>
              <dd className="text-right font-mono text-slate-300">{fmtPct(m.tools.failureRate)}</dd>
              <dt className="text-slate-500">Tool executions</dt>
              <dd className="text-right font-mono text-slate-300">{fmtNum(m.tools.totalExecutions)}</dd>
              <dt className="text-slate-500">Resource reads</dt>
              <dd className="text-right font-mono text-slate-300">{fmtNum(m.resources.totalExecutions)}</dd>
              <dt className="text-slate-500">Prompt renders</dt>
              <dd className="text-right font-mono text-slate-300">{fmtNum(m.prompts.totalExecutions)}</dd>
            </dl>
          )}
          {!m && <p className="mt-3 text-xs text-slate-500">Metrics unavailable{metrics.error ? `: ${metrics.error.message}` : ''}</p>}
        </div>

        <div className="card p-5">
          <h3 className="mb-4 text-sm font-semibold text-white">Host resources</h3>
          {v && v.system ? (
            <div className="space-y-4">
              <div>
                <div className="mb-1 flex justify-between text-xs text-slate-400">
                  <span>CPU</span>
                  <span className="font-mono">{v.system.cpu_percent}% ({v.system.cpu_count} cores)</span>
                </div>
                <Sparkline points={history.current.cpu} />
              </div>
              <div>
                <div className="mb-1 flex justify-between text-xs text-slate-400">
                  <span>Memory</span>
                  <span className="font-mono">{fmtNum(Math.round(v.system.mem_used_mb))} / {fmtNum(Math.round(v.system.mem_total_mb))} MB</span>
                </div>
                <Sparkline points={history.current.mem} color="#34d399" />
              </div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">System info unavailable.</p>
          )}
        </div>
      </section>
    </div>
  );
}
