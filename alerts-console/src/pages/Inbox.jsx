import { useCallback, useEffect, useRef, useState } from 'react';
import { useSession } from '../session.jsx';
import { useLive } from '../live.jsx';
import { SEVERITIES, SOURCES, STATUSES, relativeTime } from '../lib/format.js';
import AlertDrawer from '../components/AlertDrawer.jsx';
import { Button, ErrorBanner, Notice, Select, SeverityBadge, Spinner, StatusBadge } from '../components/ui.jsx';

const PAGE_SIZE = 25;

export default function Inbox() {
  const { api } = useSession();
  const { tick, refreshUnread, status: liveStatus } = useLive();
  const [filters, setFilters] = useState({ status: '', severity: '', source: '', unread: false });
  const [page, setPage] = useState(1);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(() => new Set());
  const [openId, setOpenId] = useState(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [message, setMessage] = useState('');
  const reqId = useRef(0);

  const load = useCallback(
    async ({ quiet = false } = {}) => {
      const id = ++reqId.current;
      if (!quiet) setLoading(true);
      try {
        const r = await api.listAlerts({ ...filters, page, pageSize: PAGE_SIZE });
        if (id !== reqId.current) return; // a newer request superseded this one
        setData(r);
        setError('');
        // Drop selections that are no longer on this page.
        setSelected((prev) => new Set([...prev].filter((x) => r.items.some((a) => a.id === x))));
      } catch (e) {
        if (id !== reqId.current) return;
        setError(e.status === 404 ? 'Alerting is not enabled on this gateway (ALERTING_ENABLED=false).' : e.message);
      } finally {
        if (id === reqId.current) setLoading(false);
      }
    },
    [api, filters, page]
  );

  useEffect(() => {
    load();
  }, [load]);

  // Live updates: refetch quietly when the stream reports a change.
  useEffect(() => {
    if (tick > 0) load({ quiet: true });
  }, [tick]); // eslint-disable-line react-hooks/exhaustive-deps

  function setFilter(key, value) {
    setPage(1);
    setSelected(new Set());
    setFilters((f) => ({ ...f, [key]: value }));
  }

  const items = data ? data.items : [];
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const allSelected = items.length > 0 && items.every((a) => selected.has(a.id));

  function toggle(id) {
    setSelected((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }

  async function bulk(action) {
    const ids = [...selected];
    setBulkBusy(true);
    setMessage('');
    setError('');
    try {
      const r = await api.bulk(action, ids);
      const failed = r.failed.length;
      setMessage(
        failed
          ? `${r.processed.length} done, ${failed} skipped (${r.failed.slice(0, 3).map((f) => f.reason).join('; ')}).`
          : `${r.processed.length} alert${r.processed.length === 1 ? '' : 's'} updated.`
      );
      setSelected(new Set());
      await load({ quiet: true });
      refreshUnread();
    } catch (e) {
      setError(e.message);
    } finally {
      setBulkBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <Select label="Status" value={filters.status} onChange={(v) => setFilter('status', v)} options={STATUSES} />
        <Select label="Severity" value={filters.severity} onChange={(v) => setFilter('severity', v)} options={SEVERITIES} />
        <Select label="Source" value={filters.source} onChange={(v) => setFilter('source', v)} options={SOURCES} />
        <label className="flex items-center gap-2 pb-2 text-sm text-slate-300">
          <input type="checkbox" checked={filters.unread} onChange={(e) => setFilter('unread', e.target.checked)} />
          Unread only
        </label>
        <div className="ml-auto flex items-center gap-3 pb-1 text-xs text-slate-400">
          <span className="inline-flex items-center gap-1.5" title="Live updates connection">
            <span className={`h-2 w-2 rounded-full ${liveStatus === 'live' ? 'bg-emerald-400' : liveStatus === 'disabled' ? 'bg-slate-500' : 'bg-amber-400'}`} />
            {{ live: 'Live', disabled: 'Live off', connecting: 'Connecting…', reconnecting: 'Reconnecting…' }[liveStatus] || 'Offline'}
          </span>
          <Button variant="ghost" onClick={() => load()}>
            Refresh
          </Button>
        </div>
      </div>

      <ErrorBanner onDismiss={() => setError('')}>{error}</ErrorBanner>
      <Notice onDismiss={() => setMessage('')}>{message}</Notice>

      {selected.size > 0 && (
        <div className="flex items-center gap-3 rounded-lg border border-brand-500/40 bg-brand-500/10 px-4 py-2 text-sm">
          <span>{selected.size} selected</span>
          <Button disabled={bulkBusy} onClick={() => bulk('read')}>Mark read</Button>
          <Button disabled={bulkBusy} onClick={() => bulk('ack')}>Acknowledge</Button>
          <Button disabled={bulkBusy} onClick={() => bulk('resolve')}>Resolve</Button>
          <Button variant="ghost" className="ml-auto" onClick={() => setSelected(new Set())}>Clear</Button>
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-ink-700">
        <table className="w-full text-left text-sm">
          <thead className="bg-ink-800 text-xs uppercase tracking-wide text-slate-400">
            <tr>
              <th className="w-10 px-3 py-2">
                <input
                  type="checkbox"
                  aria-label="Select all on this page"
                  checked={allSelected}
                  onChange={() => setSelected(allSelected ? new Set() : new Set(items.map((a) => a.id)))}
                />
              </th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Alert</th>
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Seen</th>
              <th className="px-3 py-2">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-800 bg-ink-900">
            {loading && !data && (
              <tr><td colSpan={7} className="px-3 py-8 text-center"><Spinner label="Loading alerts" /></td></tr>
            )}
            {!loading && items.length === 0 && !error && (
              <tr>
                <td colSpan={7} className="px-3 py-10 text-center text-slate-400">
                  {filters.status || filters.severity || filters.source || filters.unread ? 'No alerts match these filters.' : 'No alerts yet. When something needs attention it will show up here.'}
                </td>
              </tr>
            )}
            {items.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-ink-800/60" onClick={() => setOpenId(a.id)}>
                <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" aria-label={`Select ${a.title}`} checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                </td>
                <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    className="text-left font-medium text-slate-100 hover:underline"
                    onClick={(e) => { e.stopPropagation(); setOpenId(a.id); }}
                  >
                    {a.title}
                  </button>
                  <div className="text-xs text-slate-500">{a.type}</div>
                </td>
                <td className="px-3 py-2 text-slate-300">{a.source}</td>
                <td className="px-3 py-2"><StatusBadge status={a.status} /></td>
                <td className="px-3 py-2 text-slate-300">{a.count > 1 ? `${a.count}×` : '1×'}</td>
                <td className="px-3 py-2 text-slate-400" title={a.last_seen}>{relativeTime(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-slate-400">
        <span>{data ? `${data.total} alert${data.total === 1 ? '' : 's'}` : ''}</span>
        <div className="flex items-center gap-2">
          <Button disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
          <span>Page {page} of {totalPages}</span>
          <Button disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
        </div>
      </div>

      {openId && (
        <AlertDrawer
          alertId={openId}
          onClose={() => setOpenId(null)}
          onChanged={() => { load({ quiet: true }); refreshUnread(); }}
        />
      )}
    </div>
  );
}
