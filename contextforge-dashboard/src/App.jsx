import React, { useEffect, useState } from 'react';
import { useSession } from './session.jsx';
import { verifyConnection } from './api.js';
import ConnectScreen from './components/ConnectScreen.jsx';
import Overview from './pages/Overview.jsx';
import Registry from './pages/Registry.jsx';
import Invoker from './pages/Invoker.jsx';
import Metrics from './pages/Metrics.jsx';
import Demo from './pages/Demo.jsx';

const NAV = [
  { id: 'overview', label: 'Overview' },
  { id: 'registry', label: 'Registry' },
  { id: 'invoker', label: 'Tool Invoker' },
  { id: 'metrics', label: 'Metrics' },
  { id: 'demo', label: 'Alerting Demo' },
];

function parseHash() {
  const h = window.location.hash.replace(/^#\/?/, '');
  return NAV.some((n) => n.id === h) ? h : 'overview';
}

export default function App() {
  const { session, connected, connect, disconnect } = useSession();
  const [page, setPage] = useState(parseHash);
  const [booting, setBooting] = useState(!!session.token);
  const [invokeTarget, setInvokeTarget] = useState(null);

  // Auto-resume a saved session if the token is still accepted.
  useEffect(() => {
    if (!session.token || connected) {
      setBooting(false);
      return;
    }
    let cancelled = false;
    verifyConnection(session)
      .then(() => !cancelled && connect(session))
      .catch(() => {})
      .finally(() => !cancelled && setBooting(false));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onHash = () => setPage(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const go = (id) => {
    window.location.hash = '/' + id;
    setPage(id);
  };

  if (booting) {
    return <div className="grid h-full place-items-center text-sm text-slate-400">Resuming session...</div>;
  }
  if (!connected) return <ConnectScreen />;

  const openInInvoker = (tool) => {
    setInvokeTarget(tool.name);
    go('invoker');
  };

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-900">
        <div className="flex items-center gap-2 px-4 py-4">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-brand-500 text-sm font-bold text-white">CF</div>
          <div className="leading-tight">
            <div className="text-sm font-semibold text-white">ContextForge</div>
            <div className="text-xs text-slate-500">Dashboard</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-2">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => go(n.id)}
              className={`w-full rounded-lg px-3 py-2 text-left text-sm transition ${
                page === n.id ? 'bg-brand-500/20 font-medium text-brand-400' : 'text-slate-300 hover:bg-ink-800'
              }`}
            >
              {n.label}
            </button>
          ))}
        </nav>
        <div className="border-t border-ink-700 p-3">
          <div className="mb-2 truncate font-mono text-xs text-slate-500" title={session.base}>{session.base}</div>
          <button className="btn-ghost w-full !py-1.5" onClick={disconnect}>Disconnect</button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-7xl p-6">
          {page === 'overview' && <Overview go={go} />}
          {page === 'registry' && <Registry onInvoke={openInInvoker} />}
          {page === 'invoker' && <Invoker initialTool={invokeTarget} />}
          {page === 'metrics' && <Metrics />}
          {page === 'demo' && <Demo />}
        </div>
      </main>
    </div>
  );
}
