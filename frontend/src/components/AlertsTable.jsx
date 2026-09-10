import React, { useState } from 'react'

const STATUS_OPTIONS = [
  { value: 'firing', label: 'Firing' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'escalated', label: 'Escalated' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'false_positive', label: 'False positive' },
]

function severityClass(severity) {
  switch ((severity || '').toLowerCase()) {
    case 'critical': return 'bg-red-900/60 text-red-200 border-red-800'
    case 'high':     return 'bg-orange-900/60 text-orange-200 border-orange-800'
    case 'medium':   return 'bg-yellow-900/60 text-yellow-200 border-yellow-800'
    case 'low':      return 'bg-sky-900/60 text-sky-200 border-sky-800'
    default:         return 'bg-slate-700 text-slate-300 border-slate-600'
  }
}

function formatDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString()
}

function AlertDetail({ alert }) {
  const labels = alert.labels || {}
  const annotations = alert.annotations || {}
  return (
    <tr>
      <td colSpan={5} className="bg-slate-800/40">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-5 text-sm">
          <div className="col-span-2 md:col-span-1">
            <div className="mb-1 text-sm font-semibold uppercase tracking-wider text-slate-400">Labels</div>
            <pre className="whitespace-pre-wrap break-all font-mono text-sm text-slate-300">
              {JSON.stringify(labels, null, 2)}
            </pre>
          </div>
          <div className="col-span-2 md:col-span-1">
            <div className="mb-1 text-sm font-semibold uppercase tracking-wider text-slate-400">Annotations</div>
            <pre className="whitespace-pre-wrap break-all font-mono text-sm text-slate-300">
              {JSON.stringify(annotations, null, 2)}
            </pre>
          </div>
          <div className="col-span-1">
            <div className="mb-1 text-sm font-semibold uppercase tracking-wider text-slate-400">Starts At</div>
            <div className="text-sm text-slate-300">{formatDate(alert.starts_at)}</div>
          </div>
          {alert.generatorURL && (
            <div className="col-span-2 md:col-span-4">
              <div className="mb-1 text-sm font-semibold uppercase tracking-wider text-slate-400">Source</div>
              <a href={alert.generatorURL} target="_blank" rel="noreferrer" className="text-sm text-sky-400 hover:underline break-all">
                {alert.generatorURL}
              </a>
            </div>
          )}
        </div>
      </td>
    </tr>
  )
}

export default function AlertsTable({ alerts, onStatusChange }) {
  const [expanded, setExpanded] = useState(null)
  const [savingId, setSavingId] = useState(null)
  const [statusError, setStatusError] = useState(null)

  async function handleStatusChange(alertId, status) {
    setSavingId(alertId)
    setStatusError(null)
    try {
      await onStatusChange(alertId, status)
    } catch (error) {
      setStatusError(error.message)
    } finally {
      setSavingId(null)
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#0d1522] shadow-xl">
      <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
        <h2 className="text-base font-semibold uppercase tracking-wider text-slate-300">
          Detection results
        </h2>
        <div className="flex items-center gap-3">
          {statusError && <span className="text-xs text-red-300">{statusError}</span>}
          <span className="text-sm text-slate-400 tabular-nums">{alerts.length} items</span>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-225 w-full table-fixed text-base">
          <thead className="bg-slate-900/60">
            <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
              <th className="w-44 border-r border-slate-800 px-5 py-3 font-semibold">State</th>
              <th className="w-40 border-r border-slate-800 px-5 py-3 font-semibold">Severity</th>
              <th className="w-56 border-r border-slate-800 px-5 py-3 font-semibold">Name</th>
              <th className="border-r border-slate-800 px-5 py-3 font-semibold">Summary</th>
              <th className="w-48 px-5 py-3 font-semibold">Starts At</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/60">
            {alerts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-base text-slate-400">
                  No alerts found.
                </td>
              </tr>
            )}
            {alerts.map((a) => (
              <React.Fragment key={a.id}>
                <tr
                  className="cursor-pointer border-b border-slate-800/80 transition-colors hover:bg-cyan-400/3"
                  onClick={() => setExpanded(expanded === a.id ? null : a.id)}
                >
                  <td className="border-r border-slate-800/60 px-5 py-4 align-top">
                    <select
                      aria-label={`Update status for ${a.alert_name || 'alert'}`}
                      value={a.status || 'firing'}
                      disabled={savingId === a.id}
                      onClick={(event) => event.stopPropagation()}
                      onChange={(event) => handleStatusChange(a.id, event.target.value)}
                      className={`w-40 rounded-md border px-2.5 py-2 text-sm font-semibold outline-none transition-colors disabled:cursor-wait disabled:opacity-60 ${a.status === 'firing' ? 'border-red-800 bg-red-950/60 text-red-200' : a.status === 'resolved' ? 'border-emerald-800 bg-emerald-950/50 text-emerald-200' : 'border-slate-700 bg-slate-900 text-slate-300'} focus:border-cyan-400`}
                    >
                      {STATUS_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                    </select>
                  </td>
                  <td className="border-r border-slate-800/60 px-5 py-4 align-top">
                    <span className={`inline-flex rounded px-2.5 py-1 text-sm font-semibold border ${severityClass(a.severity)}`}>
                      {a.severity || '—'}
                    </span>
                  </td>
                  <td className="max-w-65 truncate border-r border-slate-800/60 px-5 py-4 align-top font-medium text-slate-200">
                    {a.alert_name || '—'}
                  </td>
                  <td className="max-w-[320px] truncate border-r border-slate-800/60 px-5 py-4 align-top text-slate-400">
                    {a.annotations?.description || '—'}
                  </td>
                  <td className="whitespace-nowrap px-5 py-4 align-top tabular-nums text-slate-400">
                    {formatDate(a.starts_at)}
                  </td>
                </tr>
                {expanded === a.id && <AlertDetail alert={a} />}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}