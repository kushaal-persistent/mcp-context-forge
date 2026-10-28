import { severityRank } from '../lib/format.js';

const SEV = {
  CRITICAL: 'bg-red-500/15 text-red-300 ring-red-500/40',
  HIGH: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  LOW: 'bg-sky-500/15 text-sky-300 ring-sky-500/40',
};
const STATUS = {
  open: 'bg-rose-500/10 text-rose-300 ring-rose-500/30',
  acknowledged: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
  resolved: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  expired: 'bg-slate-500/10 text-slate-400 ring-slate-500/30',
  suppressed: 'bg-slate-500/10 text-slate-400 ring-slate-500/30',
};

export function SeverityBadge({ severity }) {
  const cls = SEV[severity] || 'bg-slate-500/15 text-slate-300 ring-slate-500/40';
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${cls}`} data-rank={severityRank(severity)}>
      {severity || 'UNKNOWN'}
    </span>
  );
}

export function StatusBadge({ status }) {
  const cls = STATUS[status] || STATUS.expired;
  return <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}>{status}</span>;
}

export function Spinner({ label = 'Loading' }) {
  return (
    <span role="status" className="inline-flex items-center gap-2 text-sm text-slate-400">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-brand-400" aria-hidden="true" />
      {label}
    </span>
  );
}

export function ErrorBanner({ children, onDismiss }) {
  if (!children) return null;
  return (
    <div role="alert" className="flex items-start justify-between gap-3 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
      <span>{children}</span>
      {onDismiss && (
        <button type="button" onClick={onDismiss} className="shrink-0 text-red-300 hover:text-white" aria-label="Dismiss error">
          ✕
        </button>
      )}
    </div>
  );
}

export function Notice({ children, onDismiss }) {
  if (!children) return null;
  return (
    <div role="status" className="flex items-start justify-between gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
      <span>{children}</span>
      {onDismiss && (
        <button type="button" onClick={onDismiss} className="shrink-0 text-emerald-300 hover:text-white" aria-label="Dismiss message">
          ✕
        </button>
      )}
    </div>
  );
}

export function Button({ variant = 'default', className = '', ...props }) {
  const base = 'inline-flex items-center justify-center rounded-md px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50';
  const styles = {
    default: 'bg-ink-700 text-slate-100 hover:bg-ink-700/70',
    primary: 'bg-brand-500 text-white hover:bg-brand-600',
    ghost: 'text-slate-300 hover:bg-ink-800',
    danger: 'bg-red-600 text-white hover:bg-red-500',
  };
  return <button type="button" className={`${base} ${styles[variant]} ${className}`} {...props} />;
}

export function Select({ label, value, onChange, options, allLabel = 'All' }) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-400">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-ink-700 bg-ink-900 px-2 py-1.5 text-sm text-slate-100"
      >
        <option value="">{allLabel}</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}
