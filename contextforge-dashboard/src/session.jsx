import React, { createContext, useContext, useMemo, useState, useCallback } from 'react';
import { createApi, DEFAULT_BASE } from './api.js';

const KEY = 'contextforge-dashboard.session.v1';
const SessionCtx = createContext(null);

function load() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY) || 'null');
    if (s && typeof s === 'object') return { base: s.base || DEFAULT_BASE, token: s.token || '' };
  } catch {
    /* ignore */
  }
  return { base: DEFAULT_BASE, token: '' };
}

export function SessionProvider({ children }) {
  const [session, setSession] = useState(load);
  const [connected, setConnected] = useState(false);

  const connect = useCallback((next) => {
    localStorage.setItem(KEY, JSON.stringify(next));
    setSession(next);
    setConnected(true);
  }, []);

  const disconnect = useCallback(() => {
    localStorage.removeItem(KEY);
    setSession({ base: DEFAULT_BASE, token: '' });
    setConnected(false);
  }, []);

  const api = useMemo(() => createApi(session), [session]);
  const value = useMemo(() => ({ session, connected, connect, disconnect, api }), [session, connected, connect, disconnect, api]);
  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}

export const useSession = () => useContext(SessionCtx);
