import React, { useEffect, useState, useCallback } from 'react'
import StatsCards from './components/StatsCards.jsx'
import AlertsTable from './components/AlertsTable.jsx'
import TimeseriesChart from './components/TimeseriesChart.jsx'
import { fetchAlerts, fetchStats, fetchTimeseries, getAlertNames, updateAlertStatus } from './api.js'
import './App.css'

export default function App() {
  const [activeView, setActiveView] = useState('overview')
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total: 0, firing: 0, resolved: 0, by_severity: {} })
  const [logCount, setLogCount] = useState(0)
  const [filter, setFilter] = useState({ status: '', severity: '', alert_name: '' })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadData = useCallback(async () => {
    try {
      const [alertData, statsData] = await Promise.all([
        fetchAlerts({ ...filter, limit: 200 }),
        fetchStats(),
      ])
      setAlerts(alertData)
      setStats(statsData)
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 5000)
    return () => clearInterval(interval)
  }, [loadData])

  useEffect(() => {
    const end = new Date()
    const start = new Date(end.getTime() - 24 * 60 * 60 * 1000)
    fetchTimeseries({ start: start.toISOString(), end: end.toISOString(), interval: '1h' })
      .then(({ data = [] }) => setLogCount(data.reduce((total, point) => total + point.count, 0)))
      .catch(() => setLogCount(0))
  }, [])

  const uniqueNames = getAlertNames(alerts)
  const firingCount = stats.firing ?? 0
  const handleStatusChange = useCallback(async (alertId, status) => {
    await updateAlertStatus(alertId, status)
    await loadData()
  }, [loadData])
  const viewMeta = {
    overview: ['Operations overview', 'A live read on security signal across your environment.'],
    alerts: ['Alert queue', 'Triage, filter, and inspect active detections.'],
    logs: ['Log volume', 'Explore log activity by time bucket and severity.'],
  }

  return (
    <div className="min-h-screen bg-[#080d16] text-slate-100">
      <div className="flex min-h-screen">
        <aside className="hidden w-64 shrink-0 border-r border-slate-800 bg-[#0b111c] lg:flex lg:flex-col">
          <div className="flex h-20 items-center gap-3 border-b border-slate-800 px-6">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400 text-sm font-black text-slate-950">S</div>
            <div>
              <div className="text-sm font-bold tracking-wide text-white">SENTINEL</div>
              <div className="text-xs uppercase tracking-[0.2em] text-slate-500">Security operations</div>
            </div>
          </div>

          <nav className="flex-1 px-3 py-6" aria-label="Primary navigation">
            <div className="mb-3 px-3 text-xs font-bold uppercase tracking-[0.2em] text-slate-600">Workspace</div>
            {[
              { id: 'overview', label: 'Overview', mark: 'OV' },
              { id: 'alerts', label: 'Alert queue', mark: 'AQ', count: firingCount },
              { id: 'logs', label: 'Log volume', mark: 'LV' },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveView(item.id)}
                className={`mb-1 flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition-colors ${activeView === item.id ? 'bg-cyan-400/10 text-cyan-300 ring-1 ring-inset ring-cyan-400/20' : 'text-slate-400 hover:bg-slate-800/70 hover:text-slate-200'}`}
              >
                <span className={`flex h-7 w-7 items-center justify-center rounded-md text-xs font-bold ${activeView === item.id ? 'bg-cyan-400 text-slate-950' : 'bg-slate-800 text-slate-500'}`}>{item.mark}</span>
                <span className="flex-1 text-base">{item.label}</span>
                {item.count > 0 && <span className="rounded-full bg-red-400/15 px-2 py-0.5 text-sm font-semibold text-red-300">{item.count}</span>}
              </button>
            ))}
          </nav>

          <div className="border-t border-slate-800 p-5">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-emerald-300"><span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399]" /> Systems operational</div>
            <div className="text-sm leading-6 text-slate-500">VictoriaLogs<br />Connected on localhost:9428</div>
          </div>
        </aside>

        <main className="min-w-0 flex-1">
          <header className="border-b border-slate-800 bg-[#0b111c]/90 px-5 py-5 backdrop-blur sm:px-8">
            <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4">
              <div>
                <div className="mb-1 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-cyan-400 lg:hidden"><span className="h-2 w-2 rounded-full bg-cyan-400" /> Sentinel SOC</div>
                <h1 className="text-xl font-semibold tracking-tight text-white sm:text-2xl">{viewMeta[activeView][0]}</h1>
                <p className="mt-1 text-sm text-slate-400">{viewMeta[activeView][1]}</p>
              </div>
              <div className="flex items-center gap-3 text-xs text-slate-400">
                <span className="hidden text-sm sm:inline">Auto-refresh 5s</span>
                <span className="flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-1.5 text-sm text-emerald-300"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />Live</span>
              </div>
            </div>
            <div className="mx-auto mt-5 flex max-w-[1600px] gap-2 overflow-x-auto lg:hidden">
              {['overview', 'alerts', 'logs'].map((view) => <button key={view} type="button" onClick={() => setActiveView(view)} className={`whitespace-nowrap rounded-md px-3 py-2 text-sm font-semibold capitalize ${activeView === view ? 'bg-cyan-400 text-slate-950' : 'bg-slate-800 text-slate-400'}`}>{view === 'alerts' ? 'Alert queue' : view === 'logs' ? 'Log volume' : view}</button>)}
            </div>
          </header>

          <div className="mx-auto max-w-[1600px] px-5 py-6 sm:px-8 sm:py-8">
            {error && <div className="mb-6 flex items-center justify-between rounded-lg border border-red-400/20 bg-red-400/10 px-4 py-3 text-base text-red-200"><span>Connection issue: {error}</span><button type="button" onClick={loadData} className="font-semibold text-red-300 hover:text-white">Retry</button></div>}

            {activeView === 'overview' ? (
              <>
                <StatsCards stats={stats} logCount={logCount} />
                <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-2">
                  <button type="button" onClick={() => setActiveView('alerts')} className="rounded-lg border border-slate-800 bg-[#0d1522] p-5 text-left transition-colors hover:border-cyan-400/40 hover:bg-[#101b2b]"><div className="mb-3 text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">Triage</div><div className="text-lg font-semibold text-white">Review alert queue</div><div className="mt-1 text-base text-slate-400">Inspect firing and resolved detections.</div></button>
                  <button type="button" onClick={() => setActiveView('logs')} className="rounded-lg border border-slate-800 bg-[#0d1522] p-5 text-left transition-colors hover:border-cyan-400/40 hover:bg-[#101b2b]"><div className="mb-3 text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">Telemetry</div><div className="text-lg font-semibold text-white">Explore log volume</div><div className="mt-1 text-base text-slate-400">Open the time-series view by severity.</div></button>
                </div>
              </>
            ) : activeView === 'logs' ? (
              <>
                <div className="mb-5"><div className="text-xs font-bold uppercase tracking-[0.2em] text-cyan-400">Telemetry workspace</div><h2 className="mt-1 text-xl font-semibold text-white">Log activity by severity</h2></div>
                <TimeseriesChart />
              </>
            ) : (
              <>
                <div className="mb-5 flex flex-wrap items-center justify-between gap-3"><div><div className="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">Triage workspace</div><h2 className="mt-1 text-xl font-semibold text-white">Detection queue</h2></div><div className="text-sm text-slate-400">{alerts.length} results · updated live</div></div>
                <section className="mb-5 flex flex-wrap gap-2 rounded-lg border border-slate-800 bg-[#0d1522] p-3">
                  <select aria-label="Filter alert state" value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })} className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300 outline-none focus:border-cyan-400"><option value="">All states</option><option value="firing">Firing</option><option value="acknowledged">Acknowledged</option><option value="investigating">Investigating</option><option value="escalated">Escalated</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select>
                  <select aria-label="Filter severity" value={filter.severity} onChange={(e) => setFilter({ ...filter, severity: e.target.value })} className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300 outline-none focus:border-cyan-400"><option value="">All severities</option><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select>
                  <select aria-label="Filter rule name" value={filter.alert_name} onChange={(e) => setFilter({ ...filter, alert_name: e.target.value })} className="min-w-44 rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300 outline-none focus:border-cyan-400"><option value="">All rule names</option>{uniqueNames.map((name) => <option key={name} value={name}>{name}</option>)}</select>
                </section>
                {loading ? <div className="flex h-64 items-center justify-center rounded-lg border border-slate-800 bg-[#0d1522] text-sm text-slate-400">Loading detection queue...</div> : <AlertsTable alerts={alerts} onStatusChange={handleStatusChange} />}
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}