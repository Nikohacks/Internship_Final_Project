import React from 'react'

const CARD_DEFS = [
  { key: 'logCount', label: 'Total Logs · 24h', accent: 'text-cyan-300' },
  { key: 'total', label: 'Total Alerts', accent: 'text-slate-300' },
  { key: 'resolved', label: 'Resolved Alerts', accent: 'text-emerald-400' },
]

export default function StatsCards({ stats, logCount }) {
  const values = { ...stats, logCount }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {CARD_DEFS.map((c) => (
        <div
          key={c.key}
          className="bg-slate-800/60 border border-slate-700 rounded-xl p-5 shadow-lg"
        >
          <div className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
            {c.label}
          </div>
          <div className={`text-5xl font-bold tabular-nums ${c.accent}`}>
            {values[c.key] ?? 0}
          </div>
        </div>
      ))}
    </div>
  )
}