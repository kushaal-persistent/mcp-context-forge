import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useSession } from './session.jsx';
import { connectAlertStream } from './lib/sse.js';

// Owns the single live connection to /v1/alerts/stream for the whole app, so the sidebar
// badge, the toasts and the inbox all update from one stream.
const Ctx = createContext(null);
export const useLive = () => useContext(Ctx);

const MAX_TOASTS = 4;
const TOAST_MS = 7000;

export function LiveProvider({ children }) {
  const { api, token, logout } = useSession();
  const [status, setStatus] = useState('connecting');
  const [unread, setUnread] = useState(null);
  const [tick, setTick] = useState(0); // bumps whenever the server tells us something changed
  const [toasts, setToasts] = useState([]);
  const timers = useRef({ refresh: null });

  const refreshUnread = useCallback(async () => {
    try {
      setUnread(await api.unreadCount());
    } catch { /* the badge is a convenience; the inbox shows real errors */ }
  }, [api]);

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  useEffect(() => {
    refreshUnread();
    const stream = connectAlertStream({
      url: api.streamUrl,
      getToken: () => token,
      onStatus: setStatus,
      onEvent: (ev) => {
        if (ev.event !== 'alert') return;
        const p = ev.payload && typeof ev.payload === 'object' ? ev.payload : {};
        const id = ev.id || `${Date.now()}-${Math.random()}`;
        setToasts((t) => [...t.filter((x) => x.id !== id), { id, title: String(p.title || 'New alert'), severity: p.severity }].slice(-MAX_TOASTS));
        setTimeout(() => dismiss(id), TOAST_MS);
        // Several events can arrive together; refresh once.
        clearTimeout(timers.current.refresh);
        timers.current.refresh = setTimeout(() => {
          setTick((n) => n + 1);
          refreshUnread();
        }, 300);
      },
    });
    return () => {
      stream.stop();
      clearTimeout(timers.current.refresh);
    };
  }, [api, token, refreshUnread, dismiss]);

  // The stream is authenticated; if the gateway rejects the token, sign out.
  useEffect(() => {
    if (status === 'unauthorized') logout();
  }, [status, logout]);

  const value = useMemo(() => ({ status, unread, tick, toasts, dismiss, refreshUnread }), [status, unread, tick, toasts, dismiss, refreshUnread]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
