import React, { useCallback, useEffect, useRef, useState } from 'react';

// ---------------------------------------------------------------------------
// Alerting demo (Issue #5805). Part 1 tells the story, part 2 runs it live against an
// ISOLATED demo gateway (port 4445). Nothing here touches the main gateway on 4444.
// Everything shown in the feed comes from real API responses; nothing is simulated.
// ---------------------------------------------------------------------------

const GW = '/demo-gw';
const CTL = '/demo-ctl';

const SEV = {
  CRITICAL: 'bg-red-500/20 text-red-300 ring-1 ring-red-500/40',
  HIGH: 'bg-orange-500/20 text-orange-300 ring-1 ring-orange-500/40',
  MEDIUM: 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/40',
  LOW: 'bg-slate-500/20 text-slate-300 ring-1 ring-slate-500/40',
};
const STATUS = {
  open: 'bg-red-500/15 text-red-300',
  acknowledged: 'bg-amber-500/15 text-amber-300',
  resolved: 'bg-emerald-500/15 text-emerald-300',
  expired: 'bg-slate-500/15 text-slate-400',
  suppressed: 'bg-slate-500/15 text-slate-400',
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clock = () => new Date().toLocaleTimeString([], { hour12: false });

function Pill({ cls, children }) {
  return <span className={`badge ${cls}`}>{children}</span>;
}

// ----------------------------- Part 1: story -------------------------------

function Story() {
  const Box = ({ title, sub, tone = 'border-ink-700' }) => (
    <div className={`rounded-lg border ${tone} bg-ink-950 px-3 py-2 text-center`}>
      <div className="text-sm font-medium text-slate-100">{title}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-400">{sub}</div>}
    </div>
  );
  const Arrow = () => <div className="self-center text-slate-500">&rarr;</div>;

  return (
    <section className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        <div className="card p-5">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-red-300">The problem</div>
          <h3 className="mb-2 text-lg font-semibold text-white">Things break and nobody is told</h3>
          <ul className="space-y-2 text-sm text-slate-300">
            <li>An MCP server behind the gateway goes down. The gateway marks it unreachable, but only a log line says so.</li>
            <li>A revoked or stolen credential is replayed again and again. Each attempt is rejected, but nobody sees the pattern.</li>
            <li>Plugins, services and system components each had their own way of reporting problems, or none at all.</li>
            <li>Administrators had to watch logs to find out.</li>
          </ul>
        </div>
        <div className="card p-5">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-emerald-300">What was built</div>
          <h3 className="mb-2 text-lg font-semibold text-white">A first-class alerting capability</h3>
          <ul className="space-y-2 text-sm text-slate-300">
            <li><b className="text-slate-100">One structured model.</b> Every alert has a source, type, severity, status, dedup key and redacted metadata.</li>
            <li><b className="text-slate-100">Deduplication.</b> Repeats within a window increase a counter instead of flooding the inbox.</li>
            <li><b className="text-slate-100">Triage lifecycle.</b> open, acknowledged, resolved, with illegal transitions rejected.</li>
            <li><b className="text-slate-100">Real-time delivery.</b> Alerts are pushed to the UI over a server-sent event stream and are also available through a REST inbox.</li>
            <li><b className="text-slate-100">Access control.</b> Visibility follows the caller's team scope, and recipients are resolved per alert.</li>
          </ul>
        </div>
      </div>

      <div className="card p-5">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">How an alert flows</div>
        <div className="flex flex-wrap items-stretch gap-2">
          <div className="flex flex-col gap-2">
            <Box title="Security logger" sub="auth failures over threshold" />
            <Box title="Gateway health check" sub="peer unreachable / recovered" />
          </div>
          <Arrow />
          <Box title="Alert service" sub="validate, redact, deduplicate, resolve recipients" tone="border-brand-500/60" />
          <Arrow />
          <Box title="Database" sub="alerts + per-recipient deliveries" />
          <Arrow />
          <Box title="Dispatcher" sub="in-app delivery" />
          <Arrow />
          <div className="flex flex-col gap-2">
            <Box title="SSE stream" sub="/v1/alerts/stream" />
            <Box title="REST inbox" sub="/v1/alerts, ack, resolve" />
          </div>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          This demo exercises the in-app channel and the two producers above. Other delivery channels and plugin producers
          are part of the wider epic but are not shown here.
        </p>
      </div>
    </section>
  );
}

// ----------------------------- Part 2: live --------------------------------

export default function Demo() {
  const [env, setEnv] = useState(null); // {ctl, gw, status}
  const [token, setToken] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [log, setLog] = useState([]);
  const [sse, setSse] = useState('connecting');
  const [steps, setSteps] = useState({}); // id -> {state, note}
  const [busy, setBusy] = useState(false);
  const tokenRef = useRef('');
  const logEnd = useRef(null);

  const addLog = useCallback((msg, kind = 'info') => {
    setLog((l) => [...l.slice(-199), { t: clock(), msg, kind }]);
  }, []);
  const setStep = (id, state, note = '') => setSteps((s) => ({ ...s, [id]: { state, note } }));

  // ---- gateway + controller helpers (every call is logged so the audience sees it)
  const gw = useCallback(
    async (method, path, body, { quiet } = {}) => {
      const r = await fetch(GW + path, {
        method,
        headers: { Authorization: `Bearer ${tokenRef.current}`, 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await r.text();
      let json = null;
      try { json = JSON.parse(text); } catch { /* not json */ }
      if (!quiet) addLog(`${method} ${path} -> ${r.status}`, r.ok ? 'info' : 'warn');
      return { status: r.status, ok: r.ok, json, text };
    },
    [addLog]
  );
  const ctl = useCallback(
    async (method, path) => {
      const r = await fetch(CTL + path, { method });
      const json = await r.json().catch(() => ({}));
      addLog(`controller ${method} ${path} -> ${r.status}`, r.ok ? 'info' : 'warn');
      return json;
    },
    [addLog]
  );

  const refresh = useCallback(async () => {
    if (!tokenRef.current) return [];
    try {
      const r = await gw('GET', '/v1/alerts?page_size=50', null, { quiet: true });
      if (r.ok && r.json) {
        setAlerts(r.json.items || []);
        return r.json.items || [];
      }
    } catch { /* gateway down */ }
    return [];
  }, [gw]);

  // ---- bootstrap: demo token + environment check
  const bootstrap = useCallback(async () => {
    const e = { ctl: false, gw: false, status: null };
    try {
      const t = await (await fetch(CTL + '/demo-token')).json();
      tokenRef.current = t.token || '';
      setToken(t.token || '');
      e.ctl = !!t.token;
    } catch { /* controller down */ }
    try {
      const h = await fetch(GW + '/health');
      e.gw = h.ok;
    } catch { /* gateway down */ }
    if (e.ctl && e.gw) {
      const s = await gw('GET', '/admin/alerts/status', null, { quiet: true });
      e.status = s.ok ? s.json : null;
    }
    setEnv(e);
    return e;
  }, [gw]);

  useEffect(() => {
    bootstrap().then((e) => e.ctl && e.gw && refresh());
  }, [bootstrap, refresh]);

  // ---- live feed: SSE (authenticated, so fetch-stream rather than EventSource) + safety poll
  useEffect(() => {
    if (!token) return undefined;
    const ac = new AbortController();
    let stopped = false;
    (async () => {
      while (!stopped) {
        try {
          const r = await fetch(GW + '/v1/alerts/stream', { headers: { Authorization: `Bearer ${token}` }, signal: ac.signal });
          if (!r.ok || !r.body) throw new Error(`stream ${r.status}`);
          setSse('live');
          const reader = r.body.getReader();
          const dec = new TextDecoder();
          let buf = '';
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            let i;
            while ((i = buf.indexOf('\n\n')) >= 0) {
              const frame = buf.slice(0, i);
              buf = buf.slice(i + 2);
              if (frame.includes('event: alert')) {
                addLog('SSE push received: alert event', 'push');
                refresh();
              }
            }
          }
        } catch (e) {
          if (stopped) return;
        }
        setSse('reconnecting');
        await sleep(2000);
      }
    })();
    const poll = setInterval(refresh, 3000);
    return () => { stopped = true; ac.abort(); clearInterval(poll); };
  }, [token, addLog, refresh]);

  useEffect(() => { logEnd.current?.scrollIntoView({ block: 'nearest' }); }, [log]);

  // ---- wait helper
  const waitFor = useCallback(
    async (pred, ms, label) => {
      const t0 = Date.now();
      while (Date.now() - t0 < ms) {
        const items = await refresh();
        const hit = items.find(pred);
        if (hit) return { hit, secs: ((Date.now() - t0) / 1000).toFixed(1) };
        setStep(label.id, 'running', `waiting... ${Math.round((Date.now() - t0) / 1000)}s`);
        await sleep(1500);
      }
      return null;
    },
    [refresh]
  );

  const run = (id, fn) => async () => {
    if (busy) return;
    setBusy(true);
    setStep(id, 'running', 'working...');
    try {
      const note = await fn();
      setStep(id, 'done', note || '');
    } catch (e) {
      setStep(id, 'error', String(e.message || e));
      addLog(`Step failed: ${e.message || e}`, 'error');
    } finally {
      setBusy(false);
    }
  };

  // ---- steps
  const sCheck = run('check', async () => {
    const e = await bootstrap();
    if (!e.ctl) throw new Error('Demo controller (port 4446) is not running.');
    if (!e.gw) throw new Error('Demo gateway (port 4445) is not running.');
    if (!e.status) throw new Error('Could not read alert status from the gateway.');
    await refresh();
    return `alerting_enabled=${e.status.alerting_enabled}, sources: ${e.status.active_sources.join(', ')}, dispatcher running: ${e.status.dispatcher_running}`;
  });

  const sStart = run('start', async () => {
    const a = await ctl('POST', '/victim/start');
    if (!a.running) throw new Error('Could not start the demo MCP server.');
    const b = await ctl('POST', '/victim/register');
    if (!b.registered) throw new Error(`Registration failed: ${b.error || b.status}`);
    return 'payments-mcp-demo is running and registered in the gateway';
  });

  const sKill = run('kill', async () => {
    await ctl('POST', '/victim/stop');
    addLog('Server stopped. Gateway health check runs every 5s...', 'info');
    const r = await waitFor((a) => a.type === 'gateway_unreachable' && a.status === 'open', 60000, { id: 'kill' });
    if (!r) throw new Error('No alert appeared within 60s.');
    return `Alert raised ${r.secs}s after the outage: ${r.hit.severity} ${r.hit.type}`;
  });

  const sRestore = run('restore', async () => {
    await ctl('POST', '/victim/start');
    addLog('Server restarted. Waiting for the gateway to notice...', 'info');
    const r = await waitFor((a) => a.type === 'gateway_unreachable' && a.status === 'resolved', 90000, { id: 'restore' });
    if (!r) throw new Error('Alert was not auto-resolved within 90s.');
    return `Alert auto-resolved ${r.secs}s after recovery, with no human action`;
  });

  const sAttack = run('attack', async () => {
    const before = alerts.find((a) => a.source === 'security' && ['open', 'acknowledged'].includes(a.status));
    const r = await ctl('POST', '/attack/revoked-token');
    if (!r.ok) throw new Error(`Attack setup failed at ${r.step} (${r.status})`);
    addLog(`Revoked token replayed: ${r.replay_statuses.join(', ')} (was ${r.before_revoke} before revoke)`, 'warn');
    const t0 = Date.now();
    let hit = null;
    while (Date.now() - t0 < 20000 && !hit) {
      const items = await refresh();
      hit = items.find((a) => a.source === 'security' && ['open', 'acknowledged'].includes(a.status));
      if (hit && before && hit.id === before.id && hit.count <= before.count) hit = null;
      if (!hit) await sleep(1000);
    }
    if (!hit) throw new Error('No security alert appeared. The failed-auth threshold may not have been crossed.');
    const items = await refresh();
    const secOpen = items.filter((a) => a.source === 'security' && ['open', 'acknowledged'].includes(a.status));
    if (secOpen.length > 1) {
      return `${secOpen.length} open security alerts with the same dedup key. Expected one (possible dedup race).`;
    }
    return hit.count > 1 ? `Deduplicated: one alert, seen ${hit.count} times` : `Security alert raised: ${hit.severity} ${hit.type}`;
  });

  const sTriage = run('triage', async () => {
    const items = await refresh();
    const target = items.find((a) => a.status === 'open') || items.find((a) => a.status === 'acknowledged');
    if (!target) throw new Error('No open alert to triage. Run an incident step first.');
    const ack = await gw('POST', `/v1/alerts/${target.id}/ack`, {});
    if (!ack.ok) throw new Error(`Acknowledge failed (${ack.status})`);
    await refresh();
    await sleep(1200);
    const res = await gw('POST', `/v1/alerts/${target.id}/resolve`, {});
    if (!res.ok) throw new Error(`Resolve failed (${res.status})`);
    await refresh();
    const bad = await gw('POST', `/v1/alerts/${target.id}/ack`, {});
    return `open -> acknowledged -> resolved. Acknowledging a resolved alert is rejected: HTTP ${bad.status}${bad.json?.detail ? ` (${bad.json.detail})` : ''}`;
  });

  const sReset = run('reset', async () => {
    await ctl('POST', '/reset');
    setSteps({});
    await refresh();
    return 'Demo server stopped and unregistered. Existing alerts stay in the inbox.';
  });

  const act = async (a, verb) => {
    const r = await gw('POST', `/v1/alerts/${a.id}/${verb}`, {});
    if (!r.ok) addLog(`${verb} rejected: ${r.json?.detail || r.status}`, 'warn');
    refresh();
  };

  // ---- render
  const ready = env && env.ctl && env.gw;
  const STEPS = [
    { id: 'check', n: 1, title: 'Check the alerting system', desc: 'Ask the gateway whether alerting is enabled, which sources are active and whether the dispatcher is running.', fn: sCheck, label: 'Check status' },
    { id: 'start', n: 2, title: 'Connect a healthy MCP server', desc: 'Start a small "payments" MCP server and register it as a peer in the demo gateway.', fn: sStart, label: 'Start and register' },
    { id: 'kill', n: 3, title: 'Incident 1: the server goes down', desc: 'Stop the server. Watch the inbox: the gateway health check detects it and raises an alert, pushed live over SSE.', fn: sKill, label: 'Kill the server' },
    { id: 'restore', n: 4, title: 'Recovery: the alert resolves itself', desc: 'Bring the server back. The alert is closed automatically when the gateway sees it healthy again.', fn: sRestore, label: 'Restore the server' },
    { id: 'attack', n: 5, title: 'Incident 2: a revoked credential is replayed', desc: 'Create an API token, revoke it, then replay it 5 times. Click again to see deduplication: same alert, higher count.', fn: sAttack, label: 'Replay revoked token' },
    { id: 'triage', n: 6, title: 'Triage the alert', desc: 'Acknowledge, then resolve, an open alert. Then try an illegal transition and see it rejected.', fn: sTriage, label: 'Acknowledge and resolve' },
  ];

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-xl font-semibold text-white">Alerting and notifications: customer demo</h1>
        <p className="mt-1 text-sm text-slate-400">Issue #5805. Part 1 explains the problem and the solution. Part 2 runs it live.</p>
      </header>

      <div>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-brand-400">Part 1: the story</h2>
        <Story />
      </div>

      <div>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-brand-400">Part 2: live walkthrough</h2>
          <div className="flex items-center gap-2 text-xs">
            <Pill cls={env?.ctl ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}>controller {env?.ctl ? 'up' : 'down'}</Pill>
            <Pill cls={env?.gw ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}>demo gateway {env?.gw ? 'up' : 'down'}</Pill>
            <Pill cls={sse === 'live' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}>SSE {sse}</Pill>
          </div>
        </div>

        {env && !ready && (
          <div className="card mb-4 border-red-500/40 p-4 text-sm text-red-200">
            The demo backend is not running. Start it with <code className="font-mono">.sasva\demo\start-demo-gateway.ps1</code> and{' '}
            <code className="font-mono">node .sasva\demo\controller.cjs</code> (see the README), then reload this page.
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-2">
          {/* steps */}
          <div className="space-y-3">
            {STEPS.map((s) => {
              const st = steps[s.id] || { state: 'idle' };
              return (
                <div key={s.id} className="card p-4">
                  <div className="flex items-start gap-3">
                    <div className={`grid h-7 w-7 shrink-0 place-items-center rounded-full text-xs font-bold ${
                      st.state === 'done' ? 'bg-emerald-500 text-white' : st.state === 'error' ? 'bg-red-500 text-white' : 'bg-ink-700 text-slate-300'
                    }`}>{st.state === 'done' ? '\u2713' : s.n}</div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-semibold text-white">{s.title}</div>
                      <div className="mt-0.5 text-xs text-slate-400">{s.desc}</div>
                      {st.note && (
                        <div className={`mt-2 text-xs ${st.state === 'error' ? 'text-red-300' : st.state === 'running' ? 'text-amber-300' : 'text-emerald-300'}`}>{st.note}</div>
                      )}
                    </div>
                    <button className="btn-primary shrink-0 !py-1.5" disabled={busy || !ready} onClick={s.fn} data-testid={`step-${s.id}`}>
                      {st.state === 'running' ? 'Running...' : s.label}
                    </button>
                  </div>
                </div>
              );
            })}
            <button className="btn-ghost" disabled={busy || !ready} onClick={sReset} data-testid="step-reset">Reset demo server</button>
          </div>

          {/* feed + log */}
          <div className="space-y-4">
            <div className="card">
              <div className="flex items-center justify-between border-b border-ink-700 px-4 py-2.5">
                <div className="text-sm font-semibold text-white">Alert inbox <span className="text-slate-500">({alerts.length})</span></div>
                <div className="text-xs text-slate-500">live from /v1/alerts</div>
              </div>
              <div className="max-h-80 divide-y divide-ink-700 overflow-y-auto" data-testid="alert-feed">
                {alerts.length === 0 && <div className="px-4 py-8 text-center text-sm text-slate-500">No alerts yet. This is the "before" picture.</div>}
                {alerts.map((a) => (
                  <div key={a.id} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Pill cls={SEV[a.severity] || SEV.LOW}>{a.severity}</Pill>
                      <Pill cls={STATUS[a.status] || STATUS.expired}>{a.status}</Pill>
                      <span className="text-xs text-slate-500">{a.source}</span>
                      {a.count > 1 && <Pill cls="bg-brand-500/20 text-brand-400">seen {a.count}x</Pill>}
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">{a.title}</div>
                    <div className="mt-0.5 font-mono text-xs text-slate-500">{a.type} &middot; last seen {new Date(a.last_seen + (a.last_seen.endsWith('Z') ? '' : 'Z')).toLocaleTimeString([], { hour12: false })}</div>
                    {(a.status === 'open' || a.status === 'acknowledged') && (
                      <div className="mt-2 flex gap-2">
                        {a.status === 'open' && <button className="btn-ghost !px-2.5 !py-1 text-xs" onClick={() => act(a, 'ack')}>Acknowledge</button>}
                        <button className="btn-ghost !px-2.5 !py-1 text-xs" onClick={() => act(a, 'resolve')}>Resolve</button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="card">
              <div className="border-b border-ink-700 px-4 py-2.5 text-sm font-semibold text-white">What the app is doing <span className="font-normal text-slate-500">(real requests)</span></div>
              <div className="max-h-56 overflow-y-auto bg-ink-950 p-3 font-mono text-xs" data-testid="activity-log">
                {log.length === 0 && <div className="text-slate-600">Waiting for the first step...</div>}
                {log.map((l, i) => (
                  <div key={i} className={l.kind === 'error' ? 'text-red-300' : l.kind === 'warn' ? 'text-amber-300' : l.kind === 'push' ? 'text-emerald-300' : 'text-slate-400'}>
                    <span className="text-slate-600">{l.t}</span> {l.msg}
                  </div>
                ))}
                <div ref={logEnd} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
