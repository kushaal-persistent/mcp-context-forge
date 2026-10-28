import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { createApi } from './lib/api.js';

// Where the browser reaches the gateway. A reverse proxy (or the Vite dev proxy) forwards it.
export const API_BASE = import.meta.env.VITE_API_BASE || '/api';

// The token lives in sessionStorage: it is cleared when the tab closes and is not shared
// between tabs. localStorage would keep a bearer token on disk for as long as it is valid.
// A httpOnly cookie would be safer still, but the gateway issues bearer tokens in the
// login response body, so that needs gateway support (see README, "Security notes").
const KEY = 'cf-alerts-session';

function decodeJwt(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(decodeURIComponent(escape(atob(part))));
  } catch {
    return null;
  }
}

function load() {
  try {
    const s = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (!s || !s.token) return null;
    if (s.expiresAt && s.expiresAt <= Date.now()) {
      sessionStorage.removeItem(KEY);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

const Ctx = createContext(null);
export const useSession = () => useContext(Ctx);

export function SessionProvider({ children }) {
  const [session, setSession] = useState(load);
  const [notice, setNotice] = useState('');
  const tokenRef = useRef(session ? session.token : null);
  tokenRef.current = session ? session.token : null;

  const clear = useCallback((message = '') => {
    sessionStorage.removeItem(KEY);
    setSession(null);
    setNotice(message);
  }, []);

  // A single place that reacts to an expired or revoked token.
  const api = useMemo(
    () =>
      createApi({
        base: API_BASE,
        getToken: () => tokenRef.current,
        onUnauthorized: () => clear('Your session expired. Please sign in again.'),
      }),
    [clear]
  );

  const login = useCallback(
    async (email, password) => {
      const res = await api.login(email, password);
      const token = res.access_token;
      const claims = decodeJwt(token) || {};
      const expiresAt = claims.exp ? claims.exp * 1000 : res.expires_in ? Date.now() + res.expires_in * 1000 : null;
      const user = res.user || {};
      const next = {
        token,
        expiresAt,
        user: { email: user.email || email, fullName: user.full_name || '', isAdmin: !!user.is_admin },
      };
      sessionStorage.setItem(KEY, JSON.stringify(next));
      setNotice('');
      setSession(next);
    },
    [api]
  );

  const logout = useCallback(async () => {
    // Best effort: ask the gateway to end the session, then forget the token regardless.
    try {
      await fetch(`${API_BASE}/v1/auth/logout`, { method: 'POST', headers: { Authorization: `Bearer ${tokenRef.current}` } });
    } catch { /* offline: still sign out locally */ }
    clear('');
  }, [clear]);

  // Sign out automatically when the token expires.
  useEffect(() => {
    if (!session || !session.expiresAt) return undefined;
    const ms = session.expiresAt - Date.now();
    const t = setTimeout(() => clear('Your session expired. Please sign in again.'), Math.max(ms, 0));
    return () => clearTimeout(t);
  }, [session, clear]);

  const value = useMemo(
    () => ({ api, session, token: session ? session.token : null, user: session ? session.user : null, login, logout, notice }),
    [api, session, login, logout, notice]
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
