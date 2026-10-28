import React from 'react';

// Minimal JSON-Schema -> form renderer for flat object schemas.
// Handles string / number / integer / boolean / enum; nested objects and arrays fall back to a JSON textarea.

export function defaultsFor(schema) {
  const out = {};
  const props = (schema && schema.properties) || {};
  for (const [k, p] of Object.entries(props)) {
    if (p && p.default !== undefined) out[k] = p.default;
  }
  return out;
}

function kindOf(p) {
  if (!p) return 'json';
  if (Array.isArray(p.enum) && p.enum.length) return 'enum';
  let t = p.type;
  if (Array.isArray(t)) t = t.find((x) => x !== 'null') || t[0];
  if (!t && (p.anyOf || p.oneOf)) {
    const alt = (p.anyOf || p.oneOf).find((x) => x && x.type && x.type !== 'null');
    t = alt && alt.type;
  }
  if (t === 'string' || t === 'number' || t === 'integer' || t === 'boolean') return t;
  return 'json';
}

// Convert the raw form values into typed arguments; returns { args, errors }.
export function coerce(schema, values) {
  const props = (schema && schema.properties) || {};
  const required = new Set((schema && schema.required) || []);
  const args = {};
  const errors = {};
  for (const [k, p] of Object.entries(props)) {
    const raw = values[k];
    const kind = kindOf(p);
    const empty = raw === undefined || raw === '' || raw === null;
    if (empty) {
      if (kind === 'boolean' && raw === false) args[k] = false;
      else if (required.has(k)) errors[k] = 'Required';
      continue;
    }
    if (kind === 'number' || kind === 'integer') {
      const n = Number(raw);
      if (Number.isNaN(n)) errors[k] = 'Must be a number';
      else if (kind === 'integer' && !Number.isInteger(n)) errors[k] = 'Must be an integer';
      else args[k] = n;
    } else if (kind === 'json') {
      if (typeof raw === 'string') {
        try {
          args[k] = JSON.parse(raw);
        } catch {
          errors[k] = 'Invalid JSON';
        }
      } else args[k] = raw;
    } else {
      args[k] = raw;
    }
  }
  return { args, errors };
}

export default function SchemaForm({ schema, values, onChange, errors = {} }) {
  const props = (schema && schema.properties) || {};
  const required = new Set((schema && schema.required) || []);
  const keys = Object.keys(props);
  if (!keys.length) return <p className="text-sm text-slate-500">This tool takes no arguments.</p>;

  const set = (k, v) => onChange({ ...values, [k]: v });

  return (
    <div className="space-y-4">
      {keys.map((k) => {
        const p = props[k] || {};
        const kind = kindOf(p);
        const id = `f-${k}`;
        return (
          <div key={k}>
            <label className="label !normal-case !tracking-normal" htmlFor={id}>
              <span className="font-mono text-slate-200">{k}</span>
              {required.has(k) && <span className="ml-1 text-rose-400">*</span>}
              <span className="ml-2 text-slate-500">{kind === 'json' ? p.type || 'json' : kind}</span>
            </label>
            {kind === 'boolean' ? (
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input id={id} type="checkbox" checked={!!values[k]} onChange={(e) => set(k, e.target.checked)} className="h-4 w-4 accent-brand-500" />
                {p.title || 'Enabled'}
              </label>
            ) : kind === 'enum' ? (
              <select id={id} className="input" value={values[k] ?? ''} onChange={(e) => set(k, e.target.value)}>
                <option value="">Select...</option>
                {p.enum.map((o) => <option key={String(o)} value={o}>{String(o)}</option>)}
              </select>
            ) : kind === 'json' ? (
              <textarea
                id={id}
                rows={3}
                className="input font-mono text-xs"
                spellCheck={false}
                placeholder={p.type === 'array' ? '[ ... ]' : '{ ... }'}
                value={typeof values[k] === 'string' || values[k] === undefined ? values[k] ?? '' : JSON.stringify(values[k], null, 2)}
                onChange={(e) => set(k, e.target.value)}
              />
            ) : (
              <input
                id={id}
                className="input"
                type={kind === 'number' || kind === 'integer' ? 'number' : 'text'}
                step={kind === 'integer' ? 1 : 'any'}
                value={values[k] ?? ''}
                onChange={(e) => set(k, e.target.value)}
              />
            )}
            {p.description && <p className="mt-1 text-xs text-slate-500">{p.description}</p>}
            {errors[k] && <p className="mt-1 text-xs text-rose-400">{errors[k]}</p>}
          </div>
        );
      })}
    </div>
  );
}
