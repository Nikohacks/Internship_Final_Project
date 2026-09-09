import React, { useCallback, useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts'
import { fetchTimeseries } from '../api.js'
import './TimeseriesChart.css'

const LEVELS = [
  { key: 'critical', color: '#f87171' },
  { key: 'high', color: '#fb923c' },
  { key: 'medium', color: '#facc15' },
  { key: 'low', color: '#38bdf8' },
]

function formatBucket(value) {
  return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function inputValue(date) {
  const offset = date.getTimezoneOffset() * 60000
  return new Date(date.getTime() - offset).toISOString().slice(0, 16)
}

export default function TimeseriesChart() {
  const [preset, setPreset] = useState('24h')
  const [customRange, setCustomRange] = useState(false)
  const [startInput, setStartInput] = useState(() => inputValue(new Date(Date.now() - 24 * 60 * 60 * 1000)))
  const [endInput, setEndInput] = useState(() => inputValue(new Date()))
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadData = useCallback(async () => {
    const end = customRange ? new Date(endInput) : new Date()
    const start = customRange
      ? new Date(startInput)
      : new Date(end.getTime() - (preset === '1h' ? 3600000 : preset === '7d' ? 604800000 : 86400000))
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
      setError('Choose a valid start and end time.')
      return
    }
    setLoading(true)
    try {
      const duration = end.getTime() - start.getTime()
      const interval = duration <= 2 * 60 * 60 * 1000 ? '5m' : '1h'
      const result = await fetchTimeseries({ start: start.toISOString(), end: end.toISOString(), interval })
      const buckets = new Map()
      for (const item of result.data || []) {
        const bucket = buckets.get(item.time) || { time: item.time }
        bucket[item.level] = item.count
        buckets.set(item.time, bucket)
      }
      setRows([...buckets.values()].sort((a, b) => new Date(a.time) - new Date(b.time)))
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [customRange, endInput, preset, startInput])

  useEffect(() => { loadData() }, [loadData])

  return (
    <section className="bg-slate-800/60 border border-slate-700 rounded-xl shadow-lg p-5 mb-6">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold uppercase tracking-wider text-slate-300">Log Volume</h2>
          <p className="mt-1 text-sm text-slate-500">Counts grouped by severity</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {['1h', '24h', '7d'].map((value) => (
            <button key={value} type="button" onClick={() => { setPreset(value); setCustomRange(false) }} className={`rounded px-3 py-2 text-sm font-semibold transition-colors ${!customRange && preset === value ? 'bg-sky-500 text-slate-950' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}>
              Last {value}
            </button>
          ))}
          <button type="button" onClick={() => setCustomRange(true)} className={`rounded px-3 py-2 text-sm font-semibold transition-colors ${customRange ? 'bg-sky-500 text-slate-950' : 'bg-slate-700 text-slate-300 hover:bg-slate-600'}`}>Custom range</button>
        </div>
      </div>
      {customRange && (
        <div className="mb-5 flex flex-wrap items-end gap-3 rounded-lg border border-slate-700 bg-slate-900/60 p-4">
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-400">Start time<input type="datetime-local" value={startInput} onChange={(event) => setStartInput(event.target.value)} className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-base text-slate-200 outline-none focus:border-cyan-400" /></label>
          <label className="flex flex-col gap-1 text-sm font-medium text-slate-400">End time<input type="datetime-local" value={endInput} onChange={(event) => setEndInput(event.target.value)} className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-base text-slate-200 outline-none focus:border-cyan-400" /></label>
          <button type="button" onClick={loadData} className="rounded-md bg-cyan-400 px-4 py-2 text-base font-semibold text-slate-950 hover:bg-cyan-300">Apply range</button>
        </div>
      )}
      <div className="mb-4 flex justify-end"><button type="button" onClick={loadData} aria-label="Refresh log volume" className="rounded bg-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-600">Refresh data</button></div>
      {loading ? (
        <div className="flex h-80 items-center justify-center text-base text-slate-400">Loading log volume...</div>
      ) : error ? (
        <div className="flex h-80 items-center justify-center text-base text-red-300">Unable to load log volume: {error}</div>
      ) : rows.length === 0 ? (
        <div className="flex h-80 items-center justify-center text-base text-slate-400">No log volume data for this range.</div>
      ) : (
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={rows} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid stroke="#334155" strokeDasharray="3 3" />
            <XAxis dataKey="time" tickFormatter={formatBucket} stroke="#94a3b8" fontSize={14} tickLine={false} />
            <YAxis stroke="#94a3b8" fontSize={14} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{
                background: '#0f172a',
                border: '1px solid #334155',
                borderRadius: 8,
                fontSize: 14,
              }}
              labelFormatter={(value) => new Date(value).toLocaleString()}
              labelStyle={{ color: '#94a3b8', marginBottom: 6 }}
            />
            <Legend wrapperStyle={{ fontSize: 14 }} />
            {LEVELS.map(({ key, color }) => (
              <Line key={key} type="monotone" dataKey={key} name={key} stroke={color} strokeWidth={2} dot={false} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </section>
  )
}