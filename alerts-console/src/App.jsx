import { useEffect, useState } from 'react';
import { useSession } from './session.jsx';
import { LiveProvider, useLive } from './live.jsx';
import Login from './pages/Login.jsx';
import Inbox from './pages/Inbox.jsx';
import Preferences from './pages/Preferences.jsx';
import { Button, SeverityBadge } from './components/ui.jsx';

const ROUTES = { '#/inbox': 'Inbox', '#/preferences': 'Preferences' };

function useHashRoute() {
  const [hash, setHash] = useState(window.location.hash in ROUTES ? window.location.hash : '#/inbox');
  useEffect(() => {
    const on = () => setHash(window.location.hash in ROUTES ? window.location.hash : '#/inbox');
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return hash;
}

function Toasts() {
  const { toasts, dismiss } = useLive();
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className="pointer-events-auto flex items-start gap-3 rounded-lg border border-ink-700 bg-ink-800 p-3 shadow-lg">
          <SeverityBadge severity={t.severity} />
          <span className="flex-1 text-sm text-slate-100">{t.title}</span>
          <button type="button" onClick={() => dismiss(t.id)} className="text-slate-400 hover:text-white" aria-label="Dismiss notification">✕</button>
        </div>
      ))}
    </div>
  );
}

function Shell() {
  const { user, logout } = useSession();
  const { unread, status } = useLive();
  const route = useHashRoute();

  return (
    <div className="flex h-full">
      <nav className="flex w-56 shrink-0 flex-col border-r border-ink-700 bg-ink-900 p-4" aria-label="Main">
        <div className="mb-6 text-base font-semibold text-white">ContextForge Alerts</div>
        {Object.entries(ROUTES).map(([href, label]) => (
          <a
            key={href}
            href={href}
            aria-current={route === href ? 'page' : undefined}
            className={`mb-1 flex items-center justify-between rounded-md px-3 py-2 text-sm ${route === href ? 'bg-ink-700 text-white' : 'text-slate-300 hover:bg-ink-800'}`}
          >
            {label}
            {href === '#/inbox' && unread > 0 && (
              <span className="rounded-full bg-red-500 px-2 text-xs font-semibold text-white" aria-label={`${unread} unread`}>
                {unread > 99 ? '99+' : unread}
              </span>
            )}
          </a>
        ))}
        <div className="mt-auto space-y-2 border-t border-ink-700 pt-4 text-xs text-slate-400">
          <div className="truncate" title={user.email}>{user.email}</div>
          {status === 'disabled' && <div className="text-amber-300">Alerting is off on this gateway.</div>}
          <Button variant="ghost" className="w-full justify-start px-0" onClick={logout}>Sign out</Button>
        </div>
      </nav>
      <main className="flex-1 overflow-y-auto p-6">
        <h1 className="mb-4 text-xl font-semibold text-white">{ROUTES[route]}</h1>
        {route === '#/preferences' ? <Preferences /> : <Inbox />}
      </main>
      <Toasts />
    </div>
  );
}

export default function App() {
  const { session } = useSession();
  if (!session) return <Login />;
  return (
    <LiveProvider>
      <Shell />
    </LiveProvider>
  );
}
