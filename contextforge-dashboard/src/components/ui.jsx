import React, { useEffect, useState, useCallback, useRef } from 'react';

export function Badge({ tone = 'slate', children }) {
  const tones = {
    green: 'bg-emerald-500/15 text-emerald-300',
    red: 'bg-rose-500/15 text-rose-300',
    amber: 'bg-amber-500/15 text-amber-300',
    blue: 'bg-brand-500/20 text-brand-400',
    slate: 'bg-slate-500/15 text-slate-300',
  };
  return <span className={`badge ${tones[tone] || tones.slate}`}>{children}</span>;
}

export function Spinner({ label }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-ink-700 border-t-brand-400" />
      {label}
    </div>
  );
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="flex items-start justify-between gap-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
      <span className="break-words">{error.message || String(error)}</span>
      {onRetry && (
        <button className="btn-ghost shrink-0 !py-1" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 py-14 text-center">
      <div className="text-sm font-medium text-slate-300">{title}</div>
      {hint && <div className="max-w-md text-xs text-slate-500">{hint}</div>}
    </div>
  );
}

export function Stat({ label, value, sub, tone }) {
  const color = tone === 'bad' ? 'text-rose-300' : tone === 'good' ? 'text-emerald-300' : 'text-white';
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function JsonView({ value, maxHeight = 'max-h-96' }) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return (
    <pre className={`${maxHeight} overflow-auto rounded-lg border border-ink-700 bg-ink-950 p-3 font-mono text-xs leading-relaxed text-slate-300`}>
      {text}
    </pre>
  );
}

export function Drawer({ open, title, onClose, children }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-label={title}>
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative z-10 flex h-full w-full max-w-xl flex-col border-l border-ink-700 bg-ink-900 shadow-2xl">
        <div className="flex items-center justify-between border-b border-ink-700 px-5 py-3">
          <h3 className="truncate text-sm font-semibold text-white">{title}</h3>
          <button className="btn-ghost !px-2 !py-1" onClick={onClose} aria-label="Close">
            Close
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

// Generic async loader with refresh + optional polling.
export function useAsync(fn, deps = [], { pollMs = 0 } = {}) {
  const [state, setState] = useState({ loading: true, data: null, error: null, at: null });
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const alive = useRef(true);

  const run = useCallback(async (silent = false) => {
    if (!silent) setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const data = await fnRef.current();
      if (alive.current) setState({ loading: false, data, error: null, at: new Date() });
    } catch (error) {
      if (alive.current) setState((s) => ({ loading: false, data: silent ? s.data : null, error, at: s.at }));
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    run(false);
    let t;
    if (pollMs > 0) t = setInterval(() => run(true), pollMs);
    return () => {
      alive.current = false;
      if (t) clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { ...state, reload: () => run(false) };
}

export const fmtMs = (s) => (s == null ? '-' : s < 1 ? `${Math.round(s * 1000)} ms` : `${s.toFixed(2)} s`);
export const fmtPct = (r) => (r == null ? '-' : `${(r * 100).toFixed(r > 0 && r < 0.01 ? 2 : 1)}%`);
export const fmtNum = (n) => (n == null ? '-' : Number(n).toLocaleString());
export const fmtDate = (d) => {
  if (!d) return '-';
  const dt = new Date(d);
  return isNaN(dt) ? String(d) : dt.toLocaleString();
};
export function fmtUptime(sec) {
  if (sec == null) return '-';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${Math.floor(sec % 60)}s`;
}
