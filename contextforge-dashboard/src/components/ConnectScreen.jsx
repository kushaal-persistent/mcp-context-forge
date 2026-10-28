import React, { useState } from 'react';
import { useSession } from '../session.jsx';
import { createApi, verifyConnection, DEFAULT_BASE } from '../api.js';

export default function ConnectScreen() {
  const { session, connect } = useSession();
  const [base, setBase] = useState(session.base || DEFAULT_BASE);
  const [token, setToken] = useState(session.token || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(null);
    const clean = token.trim().replace(/^Bearer\s+/i, '');
    if (!clean) return setError('Paste a JWT bearer token.');
    setBusy(true);
    try {
      await verifyConnection({ base: base.trim(), token: clean });
      connect({ base: base.trim(), token: clean });
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <form onSubmit={submit} className="card w-full max-w-lg space-y-5 p-7">
        <div>
          <div className="mb-1 flex items-center gap-2">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-brand-500 text-sm font-bold text-white">CF</div>
            <h1 className="text-lg font-semibold text-white">ContextForge Dashboard</h1>
          </div>
          <p className="text-sm text-slate-400">Connect to a running ContextForge gateway with a JWT bearer token.</p>
        </div>

        <div>
          <label className="label" htmlFor="base">Gateway API base URL</label>
          <input id="base" className="input font-mono" value={base} onChange={(e) => setBase(e.target.value)} placeholder={DEFAULT_BASE} />
          <p className="mt-1 text-xs text-slate-500">
            Default <code className="text-slate-300">{DEFAULT_BASE}</code> uses the built-in dev proxy to your gateway (no CORS setup needed).
            A direct URL such as <code className="text-slate-300">http://localhost:4444</code> only works if the gateway allows this origin.
          </p>
        </div>

        <div>
          <label className="label" htmlFor="token">JWT bearer token</label>
          <textarea
            id="token"
            rows={4}
            className="input font-mono text-xs"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIs..."
            spellCheck={false}
          />
          <details className="mt-2 text-xs text-slate-500">
            <summary className="cursor-pointer text-slate-400">How do I get a token?</summary>
            <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-slate-300">{`In PowerShell, from the mcp-context-forge-main folder:

& "<full path to>\\node.exe" .sasva\\mint-token.js | clip

Then press Ctrl+V in the box above.
(If "node" works in your terminal, use: node .sasva\\mint-token.js | clip)`}</pre>
            <p className="mt-2">The token is kept in this browser's localStorage only and is sent only to the gateway URL above.</p>
          </details>
        </div>

        {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}

        <button className="btn-primary w-full" disabled={busy} type="submit">
          {busy ? 'Connecting...' : 'Connect'}
        </button>
      </form>
    </div>
  );
}
