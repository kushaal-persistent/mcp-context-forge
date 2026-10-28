import React from 'react';

// Horizontal bar list: [{ label, value, color? }]
export function BarList({ data, format = (v) => v, empty = 'No data' }) {
  const max = Math.max(1, ...data.map((d) => d.value || 0));
  if (!data.length) return <div className="py-6 text-center text-xs text-slate-500">{empty}</div>;
  return (
    <ul className="space-y-2.5">
      {data.map((d) => (
        <li key={d.label}>
          <div className="mb-1 flex items-center justify-between text-xs">
            <span className="truncate text-slate-300" title={d.label}>{d.label}</span>
            <span className="ml-3 shrink-0 font-mono text-slate-400">{format(d.value)}</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-ink-800">
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.max(2, ((d.value || 0) / max) * 100)}%`, background: d.color || '#5b7fff' }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

// Donut with a centre label: segments [{ label, value, color }]
export function Donut({ segments, centre, sub, size = 140 }) {
  const total = segments.reduce((a, s) => a + (s.value || 0), 0);
  const r = 52;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="flex items-center gap-5">
      <svg width={size} height={size} viewBox="0 0 140 140" role="img" aria-label="Distribution chart">
        <circle cx="70" cy="70" r={r} fill="none" stroke="#1a2142" strokeWidth="16" />
        {total > 0 &&
          segments.map((s) => {
            const len = ((s.value || 0) / total) * c;
            const el = (
              <circle
                key={s.label}
                cx="70"
                cy="70"
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth="16"
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-offset}
                transform="rotate(-90 70 70)"
              />
            );
            offset += len;
            return el;
          })}
        <text x="70" y="68" textAnchor="middle" className="fill-white" style={{ fontSize: 20, fontWeight: 600 }}>{centre}</text>
        {sub && <text x="70" y="86" textAnchor="middle" className="fill-slate-500" style={{ fontSize: 10 }}>{sub}</text>}
      </svg>
      <ul className="space-y-1.5 text-xs">
        {segments.map((s) => (
          <li key={s.label} className="flex items-center gap-2 text-slate-300">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
            {s.label}
            <span className="font-mono text-slate-500">{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Tiny sparkline of numbers
export function Sparkline({ points, color = '#7c9cff', width = 220, height = 48 }) {
  if (!points || points.length < 2) {
    return <div className="text-xs text-slate-500">Collecting samples...</div>;
  }
  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1;
  const step = width / (points.length - 1);
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(height - 4 - ((p - min) / span) * (height - 8)).toFixed(1)}`).join(' ');
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Trend">
      <path d={d} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
