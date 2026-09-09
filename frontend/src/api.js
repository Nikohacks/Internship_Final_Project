const API_BASE = '/api'

async function fetchJson(url, options = {}) {
  const resp = await fetch(`${API_BASE}${url}`, options)
  if (!resp.ok) {
    throw new Error(`API error ${resp.status}: ${resp.statusText}`)
  }
  return resp.json()
}

export function fetchAlerts(params = {}) {
  const qs = new URLSearchParams()
  // Map frontend param names to backend's expected names
  if (params.status && params.status !== '') qs.set('status', params.status)
  if (params.severity && params.severity !== '') qs.set('severity', params.severity)
  if (params.alert_name && params.alert_name !== '') qs.set('alert_name', params.alert_name)
  if (params.limit) qs.set('limit', params.limit)
  if (params.offset) qs.set('offset', params.offset)
  const suffix = qs.toString() ? `?${qs}` : ''
  return fetchJson(`/alerts${suffix}`)
}

export function fetchStats() {
  return fetchJson('/alerts/stats')
}

export function updateAlertStatus(alertId, status) {
  return fetchJson(`/alerts/${alertId}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status }),
  })
}

export function fetchTimeseries({ start, end, interval = '1h', levels = [], query = '' }) {
  const qs = new URLSearchParams({ start, end, interval })
  if (levels.length) qs.set('levels', levels.join(','))
  if (query) qs.set('query', query)
  return fetchJson(`/logs/timeseries?${qs}`)
}

// Helper to extract unique alert names from alerts data
export function getAlertNames(alerts) {
  return [...new Set(alerts.map(a => a.alert_name))].sort()
}