import { useEffect, useState } from 'react';
import { useSession } from '../session.jsx';
import { SEVERITIES, SOURCES } from '../lib/format.js';
import { Button, ErrorBanner, Notice, Spinner } from '../components/ui.jsx';

// Email is not built in the backend yet, so only in-app and webhook are offered.
const CHANNELS = ['in_app', 'webhook'];
const SEV_ASC = [...SEVERITIES].reverse(); // LOW..CRITICAL

const blank = (scope = 'global', scope_value = '', channel = 'in_app') => ({
  scope,
  scope_value,
  channel,
  min_severity: 'LOW',
  enabled: true,
  mute_until: null,
  quiet_hours: null,
});

// Strip server-only fields before sending the rows back.
const toPayload = (r) => ({
  scope: r.scope,
  scope_value: r.scope === 'global' ? '' : r.scope_value,
  channel: r.channel,
  min_severity: r.min_severity,
  enabled: r.enabled,
  mute_until: r.mute_until || null,
  quiet_hours: r.quiet_hours || null,
});

export default function Preferences() {
  const { api } = useSession();
  const [rows, setRows] = useState(null);
  const [defaults, setDefaults] = useState([]);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    const ctl = new AbortController();
    api
      .getPreferences(ctl.signal)
      .then((r) => {
        setRows(r.items.filter((i) => !i.is_default && i.scope !== 'entity'));
        setDefaults(r.items.filter((i) => i.is_default));
      })
      .catch((e) => e.name !== 'AbortError' && setError(e.message));
    return () => ctl.abort();
  }, [api]);

  function update(i, patch) {
    setRows((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
    setDirty(true);
    setSaved('');
  }
  function remove(i) {
    setRows((rs) => rs.filter((_, idx) => idx !== i));
    setDirty(true);
    setSaved('');
  }
  function add(row) {
    setRows((rs) => [...rs, row]);
    setDirty(true);
    setSaved('');
  }

  async function save() {
    setSaving(true);
    setError('');
    try {
      const r = await api.savePreferences(rows.map(toPayload));
      setRows(r.items.filter((i) => !i.is_default && i.scope !== 'entity'));
      setDefaults(r.items.filter((i) => i.is_default));
      setDirty(false);
      setSaved('Preferences saved.');
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  }

  if (!rows && !error) return <Spinner label="Loading preferences" />;

  const hasGlobal = (ch) => rows && rows.some((r) => r.scope === 'global' && r.channel === ch);

  return (
    <div className="max-w-3xl space-y-5">
      <p className="text-sm text-slate-400">
        Choose which alerts reach you. A rule for a specific source overrides your global rule for the same channel.
      </p>

      <Notice>{saved}</Notice>
      <ErrorBanner onDismiss={() => setError('')}>{error}</ErrorBanner>

      {rows && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          Only in-app delivery is available today. Webhook rules are saved but nothing is sent until webhook delivery is
          added to the gateway.
        </div>
      )}

      {rows && (
        <div className="overflow-hidden rounded-lg border border-ink-700">
          <table className="w-full text-left text-sm">
            <thead className="bg-ink-800 text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-3 py-2">Applies to</th>
                <th className="px-3 py-2">Channel</th>
                <th className="px-3 py-2">Minimum severity</th>
                <th className="px-3 py-2">On</th>
                <th className="px-3 py-2"><span className="sr-only">Remove</span></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800 bg-ink-900">
              {rows.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-slate-400">No rules yet. Administrator defaults apply.</td></tr>
              )}
              {rows.map((r, i) => (
                <tr key={`${r.scope}-${r.scope_value}-${r.channel}-${i}`}>
                  <td className="px-3 py-2">
                    {r.scope === 'global' ? (
                      'Everything'
                    ) : (
                      <select
                        aria-label="Source"
                        value={r.scope_value}
                        onChange={(e) => update(i, { scope_value: e.target.value })}
                        className="rounded-md border border-ink-700 bg-ink-950 px-2 py-1"
                      >
                        {SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
                      </select>
                    )}
                  </td>
                  <td className="px-3 py-2">{r.channel}</td>
                  <td className="px-3 py-2">
                    <select
                      aria-label="Minimum severity"
                      value={r.min_severity}
                      onChange={(e) => update(i, { min_severity: e.target.value })}
                      className="rounded-md border border-ink-700 bg-ink-950 px-2 py-1"
                    >
                      {SEV_ASC.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </td>
                  <td className="px-3 py-2">
                    <input type="checkbox" aria-label="Enabled" checked={r.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Button variant="ghost" onClick={() => remove(i)} aria-label="Remove rule">Remove</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {rows && (
        <div className="flex flex-wrap items-center gap-2">
          {CHANNELS.filter((c) => !hasGlobal(c)).map((c) => (
            <Button key={c} onClick={() => add(blank('global', '', c))}>Add global {c} rule</Button>
          ))}
          <Button onClick={() => add(blank('category', SOURCES[0], 'in_app'))}>Add rule for a source</Button>
          <Button variant="primary" className="ml-auto" disabled={!dirty || saving} onClick={save}>
            {saving ? 'Saving…' : 'Save changes'}
          </Button>
        </div>
      )}

      {defaults.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium text-slate-300">Administrator defaults (read only)</h3>
          <ul className="space-y-1 text-sm text-slate-400">
            {defaults.map((d) => (
              <li key={d.id}>
                {d.scope === 'global' ? 'Everything' : d.scope_value} via {d.channel}, {d.min_severity} and above, {d.enabled ? 'on' : 'off'}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
