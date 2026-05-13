import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, LogIn, Moon, RefreshCw, Shield, Sun } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { AlertTable } from '../components/AlertTable.jsx';
import { DetectionForm } from '../components/DetectionForm.jsx';
import { MetricTile } from '../components/MetricTile.jsx';
import { fetchAlerts, fetchStats, login } from '../lib/api.js';
import { normalizeBackendTimestamp } from '../lib/datetime.js';
import { useLiveAlerts } from '../lib/useLiveAlerts.js';

export default function App() {
  const [dark, setDark] = useState(true);
  const [filter, setFilter] = useState('');
  const [loginState, setLoginState] = useState({ email: '', password: '' });
  const [scanResult, setScanResult] = useState(null);
  const [authError, setAuthError] = useState('');
  const [token, setToken] = useState(localStorage.getItem('shank_token'));

  const statsQuery = useQuery({ queryKey: ['stats'], queryFn: fetchStats, enabled: Boolean(token) });
  const alertsQuery = useQuery({ queryKey: ['alerts'], queryFn: fetchAlerts, enabled: Boolean(token) });
  const live = useLiveAlerts(token);

  const alerts = useMemo(() => {
    const byId = new Map();
    [...live.events, ...(alertsQuery.data || [])].forEach((alert) => byId.set(alert.id, alert));
    return Array.from(byId.values()).sort(
      (a, b) => normalizeBackendTimestamp(b.created_at) - normalizeBackendTimestamp(a.created_at)
    );
  }, [alertsQuery.data, live.events]);

  const severityData = Object.entries(statsQuery.data?.severity || {}).map(([severity, count]) => ({
    severity,
    count
  }));

  async function handleLogin(event) {
    event.preventDefault();
    setAuthError('');
    try {
      const data = await login(loginState.email, loginState.password);
      setToken(data.access_token);
      statsQuery.refetch();
      alertsQuery.refetch();
    } catch (error) {
      setAuthError(error.response?.data?.detail || 'Login failed');
    }
  }

  return (
    <main className={dark ? 'dark min-h-screen bg-slate-950 text-slate-100' : 'min-h-screen bg-slate-100 text-slate-950'}>
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6 px-4 py-5 sm:px-6 lg:px-8">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-lg bg-teal-600">
              <Shield className="h-6 w-6 text-white" aria-hidden="true" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-normal">SHANK</h1>
              <p className="text-sm text-slate-400">Real-time phishing detection operations</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`rounded px-2 py-1 text-xs ${live.connected ? 'bg-teal-700' : 'bg-slate-700'}`}>
              {live.connected ? 'Live' : 'Offline'}
            </span>
            <button className="rounded-md border border-slate-700 p-2" onClick={() => statsQuery.refetch()} title="Refresh">
              <RefreshCw className="h-4 w-4" />
            </button>
            <button className="rounded-md border border-slate-700 p-2" onClick={() => setDark(!dark)} title="Toggle dark mode">
              {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
          </div>
        </header>

        {!token && (
          <form onSubmit={handleLogin} className="grid gap-3 rounded-lg border border-slate-800 bg-slate-950 p-4 md:grid-cols-[1fr_1fr_auto]">
            <input
              value={loginState.email}
              onChange={(event) => setLoginState({ ...loginState, email: event.target.value })}
              className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-slate-100"
              placeholder="Email"
            />
            <input
              type="password"
              value={loginState.password}
              onChange={(event) => setLoginState({ ...loginState, password: event.target.value })}
              className="h-10 rounded-md border border-slate-700 bg-slate-900 px-3 text-slate-100"
              placeholder="Password"
            />
            <button className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-teal-600 px-4 font-semibold text-white">
              <LogIn className="h-4 w-4" />
              Login
            </button>
            {authError && <p className="text-sm text-red-400 md:col-span-3">{authError}</p>}
          </form>
        )}

        <section className="grid gap-4 md:grid-cols-4">
          <MetricTile label="Events" value={statsQuery.data?.events ?? 0} />
          <MetricTile label="Alerts" value={statsQuery.data?.alerts ?? 0} tone="warning" />
          <MetricTile label="Critical" value={statsQuery.data?.severity?.critical ?? 0} tone="danger" />
          <MetricTile label="High" value={statsQuery.data?.severity?.high ?? 0} tone="success" />
        </section>

        <section className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="flex flex-col gap-4">
            <DetectionForm onResult={setScanResult} />
            {scanResult && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                <div className="flex items-center gap-2 text-slate-300">
                  <Activity className="h-5 w-5 text-teal-400" />
                  <span className="font-medium">Latest analysis</span>
                </div>
                <div className="mt-3 grid gap-3 sm:grid-cols-4">
                  <MetricTile label="Risk" value={scanResult.risk_score} tone={scanResult.risk_score >= 70 ? 'danger' : 'success'} />
                  <MetricTile label="Severity" value={scanResult.severity} />
                  <MetricTile label="Confidence" value={`${scanResult.confidence}%`} />
                  <MetricTile label="Phishing" value={`${Math.round(scanResult.phishing_probability * 100)}%`} />
                </div>
              </div>
            )}
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h2 className="text-base font-semibold">Severity Trend</h2>
            <div className="mt-4 h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData}>
                  <CartesianGrid stroke="#1e293b" />
                  <XAxis dataKey="severity" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#020617', border: '1px solid #1e293b' }} />
                  <Bar dataKey="count" fill="#0f766e" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Recent Alerts</h2>
            <input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              className="h-10 w-full rounded-md border border-slate-700 bg-slate-900 px-3 text-slate-100 outline-none focus:border-teal-500 sm:w-80"
              placeholder="Filter alerts"
            />
          </div>
          <AlertTable alerts={alerts} filter={filter} />
        </section>
      </div>
    </main>
  );
}
