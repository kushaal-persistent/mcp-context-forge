import { useEffect, useState } from 'react';
import { useSession } from '../session.jsx';
import { absoluteTime, allowedActions, relativeTime } from '../lib/format.js';
import { Button, ErrorBanner, SeverityBadge, Spinner, StatusBadge } from './ui.jsx';

function Row({ label, children }) {
  return (
    <div className="grid grid-cols-3 gap-3 border-b border-ink-800 py-2 text-sm">
      <dt className="text-slate-400">{label}</dt>
      <dd className="col-span-2 break-words text-slate-100">{children ?? '-'}</dd>
    </div>
  );
}

export default function AlertDrawer({ alertId, onClose, onChanged }) {
  const { api } = useSession();
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');

  useEffect(() => {
    const ctl = new AbortController();
    setAlert(null);
    setError('');
    api.getAlert(alertId, ctl.signal).then(setAlert).catch((e) => e.name !== 'AbortError' && setError(e.message));
    return () => ctl.abort();
  }, [api, alertId]);

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function act(kind) {
    setBusy(kind);
    setError('');
    try {
      const updated = await (kind === 'ack' ? api.acknowledge(alertId) : api.resolve(alertId));
      setAlert(updated);
      onChanged();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy('');
    }
  }

  const can = alert ? allowedActions(alert) : { ack: false, resolve: false };
  const meta = alert && alert.metadata && Object.keys(alert.metadata).length ? JSON.stringify(alert.metadata, null, 2) : '';

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true" aria-label="Alert details">
      <button type="button" className="absolute inset-0 bg-black/50" onClick={onClose} aria-label="Close details" tabIndex={-1} />
      <aside className="relative z-10 flex h-full w-full max-w-lg flex-col overflow-y-auto border-l border-ink-700 bg-ink-900 p-6 shadow-2xl">
        <div className="mb-4 flex items-start justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">{alert ? alert.title : 'Alert'}</h2>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white" aria-label="Close">
            ✕
          </button>
        </div>

        <ErrorBanner onDismiss={() => setError('')}>{error}</ErrorBanner>
        {!alert && !error && <Spinner />}

        {alert && (
          <>
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
              {alert.count > 1 && <span className="text-xs text-slate-400">seen {alert.count}×</span>}
            </div>
            <p className="mb-4 whitespace-pre-wrap text-sm text-slate-300">{alert.body}</p>

            <div className="mb-5 flex gap-2">
              <Button variant="primary" disabled={!can.ack || !!busy} onClick={() => act('ack')}>
                {busy === 'ack' ? 'Acknowledging…' : 'Acknowledge'}
              </Button>
              <Button disabled={!can.resolve || !!busy} onClick={() => act('resolve')}>
                {busy === 'resolve' ? 'Resolving…' : 'Resolve'}
              </Button>
            </div>

            <dl>
              <Row label="Source">{alert.source}</Row>
              <Row label="Type">{alert.type}</Row>
              <Row label="Entity">{alert.entity_type ? `${alert.entity_type}: ${alert.entity_id || '-'}` : null}</Row>
              <Row label="First seen">{`${absoluteTime(alert.first_seen)} (${relativeTime(alert.first_seen)})`}</Row>
              <Row label="Last seen">{`${absoluteTime(alert.last_seen)} (${relativeTime(alert.last_seen)})`}</Row>
              <Row label="Acknowledged">{alert.ack_by ? `${alert.ack_by}, ${absoluteTime(alert.ack_at)}` : null}</Row>
              <Row label="Resolved">{alert.resolved_at ? `${absoluteTime(alert.resolved_at)}${alert.resolved_by ? ` by ${alert.resolved_by}` : ''}` : null}</Row>
              <Row label="Alert ID">
                <code className="text-xs">{alert.id}</code>
              </Row>
            </dl>

            {meta && (
              <>
                <h3 className="mb-2 mt-5 text-sm font-medium text-slate-300">Details</h3>
                {/* Rendered as text by React, never as HTML. The server already redacts secrets. */}
                <pre className="overflow-x-auto rounded-md bg-ink-950 p-3 text-xs text-slate-300">{meta}</pre>
              </>
            )}
          </>
        )}
      </aside>
    </div>
  );
}
