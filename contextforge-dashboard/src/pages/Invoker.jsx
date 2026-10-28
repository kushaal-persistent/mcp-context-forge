import React, { useEffect, useMemo, useState } from 'react';
import { useSession } from '../session.jsx';
import { Badge, Empty, ErrorBox, JsonView, Spinner, useAsync } from '../components/ui.jsx';
import SchemaForm, { coerce, defaultsFor } from '../components/SchemaForm.jsx';

const HISTORY_KEY = 'contextforge-dashboard.invoke-history.v1';

const loadHistory = () => {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch {
    return [];
  }
};

// MCP tool results carry content blocks; show text blocks readably.
function ResultView({ outcome }) {
  const { ok, result, error, ms, raw } = outcome;
  const blocks = result && Array.isArray(result.content) ? result.content : null;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Badge tone={ok ? 'green' : 'red'}>{ok ? 'success' : 'error'}</Badge>
        <span className="font-mono text-xs text-slate-400">{ms} ms</span>
      </div>
      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
          {error.message || JSON.stringify(error)}
          {error.code !== undefined && <span className="ml-2 font-mono text-xs text-rose-300/70">code {error.code}</span>}
        </div>
      )}
      {blocks &&
        blocks.map((b, i) =>
          b.type === 'text' ? (
            <div key={i}>
              <div className="label">Text output</div>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-xs text-slate-200">{b.text}</pre>
            </div>
          ) : (
            <div key={i}>
              <div className="label">{b.type} block</div>
              <JsonView value={b} maxHeight="max-h-48" />
            </div>
          )
        )}
      <details>
        <summary className="cursor-pointer text-xs text-slate-400">Raw JSON-RPC response</summary>
        <div className="mt-2"><JsonView value={raw} /></div>
      </details>
    </div>
  );
}

export default function Invoker({ initialTool }) {
  const { api } = useSession();
  const { loading, data: tools, error, reload } = useAsync(() => api.tools(), [api]);
  const [name, setName] = useState(initialTool || '');
  const [filter, setFilter] = useState('');
  const [mode, setMode] = useState('form');
  const [values, setValues] = useState({});
  const [rawJson, setRawJson] = useState('{}');
  const [fieldErrors, setFieldErrors] = useState({});
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState(null);
  const [callError, setCallError] = useState(null);
  const [history, setHistory] = useState(loadHistory);

  const list = tools || [];
  const tool = useMemo(() => list.find((t) => t.name === name) || null, [list, name]);
  const visible = useMemo(() => {
    const n = filter.trim().toLowerCase();
    return list.filter((t) => t.enabled !== false && (!n || [t.name, t.displayName, t.description].some((s) => s && s.toLowerCase().includes(n))));
  }, [list, filter]);

  // Reset the form whenever the selected tool changes.
  useEffect(() => {
    const d = defaultsFor(tool && tool.input_schema);
    setValues(d);
    setRawJson(JSON.stringify(d, null, 2));
    setFieldErrors({});
    setOutcome(null);
    setCallError(null);
  }, [tool && tool.id]);

  function switchMode(next) {
    if (next === mode) return;
    if (next === 'json') {
      const { args } = coerce(tool.input_schema, values);
      setRawJson(JSON.stringify(args, null, 2));
    } else {
      try {
        const parsed = JSON.parse(rawJson || '{}');
        if (parsed && typeof parsed === 'object') setValues(parsed);
      } catch {
        /* keep current form values */
      }
    }
    setMode(next);
  }

  async function run() {
    if (!tool) return;
    setCallError(null);
    setOutcome(null);
    let args;
    if (mode === 'json') {
      try {
        args = JSON.parse(rawJson || '{}');
        if (args === null || typeof args !== 'object' || Array.isArray(args)) throw new Error('Arguments must be a JSON object');
      } catch (e) {
        return setCallError(new Error(`Invalid JSON: ${e.message}`));
      }
    } else {
      const c = coerce(tool.input_schema, values);
      setFieldErrors(c.errors);
      if (Object.keys(c.errors).length) return;
      args = c.args;
    }
    setBusy(true);
    try {
      const out = await api.callTool(tool.name, args);
      setOutcome(out);
      const entry = { at: Date.now(), name: tool.name, args, ok: out.ok, ms: out.ms };
      const next = [entry, ...history].slice(0, 15);
      setHistory(next);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
    } catch (e) {
      setCallError(e);
    } finally {
      setBusy(false);
    }
  }

  function replay(h) {
    setName(h.name);
    setMode('json');
    setRawJson(JSON.stringify(h.args, null, 2));
    setOutcome(null);
  }

  if (loading && !tools) return <Spinner label="Loading tools..." />;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Tool Invoker</h2>
          <p className="text-sm text-slate-400">Call any enabled tool through the gateway (JSON-RPC <code className="text-slate-300">tools/call</code>).</p>
        </div>
        <button className="btn-ghost" onClick={reload}>Reload tools</button>
      </header>

      {error && <ErrorBox error={error} onRetry={reload} />}

      {list.length === 0 && !error ? (
        <div className="card"><Empty title="No tools registered" hint="Register a peer gateway or REST tool in ContextForge, then reload. Tools federated from MCP servers appear here automatically." /></div>
      ) : (
        <div className="grid gap-5 lg:grid-cols-[300px_1fr]">
          <div className="card flex max-h-[70vh] flex-col overflow-hidden">
            <div className="border-b border-ink-700 p-3">
              <input className="input" placeholder="Filter tools..." value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter tools" />
            </div>
            <ul className="flex-1 divide-y divide-ink-800 overflow-y-auto" aria-label="Tools">
              {visible.map((t) => (
                <li key={t.id}>
                  <button
                    onClick={() => setName(t.name)}
                    className={`w-full px-4 py-2.5 text-left transition hover:bg-ink-800 ${t.name === name ? 'bg-brand-500/15' : ''}`}
                  >
                    <div className="truncate text-sm font-medium text-white">{t.displayName || t.name}</div>
                    <div className="truncate text-xs text-slate-500">{t.gateway_slug || t.integration_type}</div>
                  </button>
                </li>
              ))}
              {visible.length === 0 && <li className="p-4 text-xs text-slate-500">No enabled tools match.</li>}
            </ul>
          </div>

          <div className="space-y-5">
            {!tool ? (
              <div className="card"><Empty title="Select a tool" hint="Pick a tool from the list to build its arguments and run it." /></div>
            ) : (
              <>
                <div className="card space-y-5 p-5">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="truncate font-mono text-sm font-semibold text-white">{tool.name}</h3>
                      {tool.description && <p className="mt-1 text-sm text-slate-400">{tool.description}</p>}
                      {tool.reachable === false && <div className="mt-2"><Badge tone="amber">reported unreachable</Badge></div>}
                    </div>
                    <div className="flex rounded-lg border border-ink-700 p-0.5 text-xs">
                      {['form', 'json'].map((m) => (
                        <button key={m} onClick={() => switchMode(m)} className={`rounded-md px-3 py-1 ${mode === m ? 'bg-brand-500 text-white' : 'text-slate-300'}`}>
                          {m === 'form' ? 'Form' : 'Raw JSON'}
                        </button>
                      ))}
                    </div>
                  </div>

                  {mode === 'form' ? (
                    <SchemaForm schema={tool.input_schema} values={values} onChange={setValues} errors={fieldErrors} />
                  ) : (
                    <div>
                      <label className="label" htmlFor="raw">Arguments (JSON object)</label>
                      <textarea id="raw" rows={9} className="input font-mono text-xs" spellCheck={false} value={rawJson} onChange={(e) => setRawJson(e.target.value)} />
                    </div>
                  )}

                  <ErrorBox error={callError} />
                  <button className="btn-primary" onClick={run} disabled={busy}>{busy ? 'Running...' : 'Run tool'}</button>
                </div>

                {outcome && <div className="card p-5"><ResultView outcome={outcome} /></div>}
              </>
            )}

            {history.length > 0 && (
              <div className="card p-5">
                <div className="mb-3 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">Recent calls</h3>
                  <button className="text-xs text-slate-400 hover:text-white" onClick={() => { setHistory([]); localStorage.removeItem(HISTORY_KEY); }}>Clear</button>
                </div>
                <ul className="divide-y divide-ink-800 text-sm">
                  {history.map((h) => (
                    <li key={h.at} className="flex items-center justify-between gap-3 py-2">
                      <div className="min-w-0">
                        <span className="font-mono text-slate-200">{h.name}</span>
                        <span className="ml-2 text-xs text-slate-500">{new Date(h.at).toLocaleTimeString()} - {h.ms} ms</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge tone={h.ok ? 'green' : 'red'}>{h.ok ? 'ok' : 'error'}</Badge>
                        <button className="btn-ghost !py-1" onClick={() => replay(h)}>Replay</button>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
