import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react';
import { Activity, AlertTriangle, ArrowRight, Bug, CheckCircle2, CircleAlert, Clock3, Fingerprint, Plus, RefreshCw, Shield, ShieldCheck, Target } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { apiRequest, userFacingError } from '../services/api';

type Health = { status: string; database: string; version: string };
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
type ScanSummary = { id: string; name: string; target_name: string; status: string; profile: string; started_at: string; findings_count: number };
type RecentScan = { id: string; name: string; target_name: string; status: string; profile: string; started_at: string; duration_seconds: number | null; findings_count: number };
type FindingSummary = { id: string; title: string; severity: Severity; category: string; status: string; target_name: string; detected_at: string };
type Summary = {
  generated_at: string; total_scans: number; targets_assessed: number; open_findings: number; critical_high_findings: number;
  severity_counts: Record<Severity, number>; comparisons: Record<string, number | null>;
  recent_scans: ScanSummary[]; recent_findings: FindingSummary[];
};
type ActivityPoint = { date: string; scans: number; findings: number };
type RecentScansResponse = { items?: RecentScan[]; total?: number };

const severityLabels: Record<Severity, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational',
};
const severityColors: Record<Severity, string> = {
  critical: '#fb7185', high: '#f9735b', medium: '#fbbf24', low: '#22d3ee', informational: '#8b9bb0',
};
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
function dateLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(date);
}
function dateTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function durationLabel(value: number | null) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  return value < 60 ? `${value.toFixed(1)} s` : `${Math.floor(value / 60)}m ${Math.floor(value % 60)}s`;
}

export default function Overview() {
  const [health, setHealth] = useState<Health | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [activity, setActivity] = useState<ActivityPoint[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [recentTotal, setRecentTotal] = useState(0);
  const [recentPage, setRecentPage] = useState(1);
  const [recentSearchDraft, setRecentSearchDraft] = useState('');
  const [recentQuery, setRecentQuery] = useState('');
  const [recentSort, setRecentSort] = useState<'started_at' | 'findings_count'>('started_at');
  const [recentDirection, setRecentDirection] = useState<'asc' | 'desc'>('desc');
  const [recentLoading, setRecentLoading] = useState(true);
  const [recentError, setRecentError] = useState<string | null>(null);
  const [days, setDays] = useState(14);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [healthResult, summaryResult, activityResult] = await Promise.all([
        apiRequest<Health>('/api/health'),
        apiRequest<Summary>('/api/dashboard/summary'),
        apiRequest<{ items: ActivityPoint[] }>(`/api/dashboard/activity?days=${days}`),
      ]);
      setHealth(healthResult);
      setSummary(summaryResult);
      setActivity(activityResult.items);
    } catch (reason) {
      setError(userFacingError(reason, 'Dashboard data could not be loaded.'));
      setHealth(null);
      setSummary(null);
      setActivity([]);
    } finally {
      setLoading(false);
    }
  }, [days]);
  useEffect(() => { void load(); }, [load]);

  const loadRecentScans = useCallback(async () => {
    setRecentLoading(true);
    setRecentError(null);
    const params = new URLSearchParams({ page: String(recentPage), page_size: '5', sort: recentSort, direction: recentDirection });
    if (recentQuery) params.set('query', recentQuery);
    try {
      const result = await apiRequest<RecentScansResponse>(`/api/scans?${params.toString()}`);
      setRecentScans(Array.isArray(result.items) ? result.items : []);
      setRecentTotal(typeof result.total === 'number' ? result.total : 0);
    } catch (reason) {
      setRecentScans([]);
      setRecentTotal(0);
      setRecentError(userFacingError(reason, 'Recent scans could not be loaded.'));
    } finally {
      setRecentLoading(false);
    }
  }, [recentDirection, recentPage, recentQuery, recentSort]);
  useEffect(() => { void loadRecentScans(); }, [loadRecentScans]);

  function submitRecentSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRecentPage(1);
    setRecentQuery(recentSearchDraft.trim());
  }

  const severityData = useMemo(() => severityOrder.map((key) => ({
    key, label: severityLabels[key], value: summary?.severity_counts[key] ?? 0,
  })), [summary]);
  const totalActive = severityData.reduce((total, item) => total + item.value, 0);
  const currentActivityTotal = activity.reduce((total, item) => total + item.scans, 0);

  return (
    <div className="overview-page">
      <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> OVERVIEW</div>
      <div className="welcome-row">
        <div><h1>Security Overview</h1><p className="page-subtitle">Monitor, assess, and improve your web application security.</p></div>
        <div className="welcome-actions"><Link to="/reports" className="button button-secondary">View Reports <ArrowRight size={15} /></Link><Link to="/scan/new" className="button button-primary"><Plus size={16} /> Start New Scan</Link></div>
      </div>
      <div className="system-status" role="status" aria-live="polite">
        {health ? <><CheckCircle2 size={16} /><span>Application API connected</span><span className="status-separator">·</span><span>{health.database.toUpperCase()} persistence ready</span><span className="status-fill" /><span className="status-version">API {health.version}</span></> : error ? <><CircleAlert size={16} /><span>Dashboard API unavailable</span><span className="status-fill" /><button className="text-button" type="button" onClick={() => void load()}>Retry</button></> : <><span className="loading-dot" /><span>Checking API and loading persisted data…</span></>}
      </div>
      {error && <div className="form-alert page-alert" role="alert">{error}<button className="text-button" type="button" onClick={() => void load()}>Try again</button></div>}

      {loading && !summary ? <div className="panel-loading" role="status"><span className="loading-dot" /> Loading dashboard metrics from the database…</div> : summary && <>
        <section className="metric-grid" aria-label="Persisted workspace metrics">
          <article className="metric-card"><span className="metric-icon cyan"><Activity size={17} /></span><div><span className="metric-label">Total scans</span><strong>{summary.total_scans.toLocaleString()}</strong><small>All recorded job states</small></div></article>
          <article className="metric-card"><span className="metric-icon violet"><Target size={17} /></span><div><span className="metric-label">Targets assessed</span><strong>{summary.targets_assessed.toLocaleString()}</strong><small>Targets with completed scans</small></div></article>
          <article className="metric-card"><span className="metric-icon amber"><Bug size={17} /></span><div><span className="metric-label">Open findings</span><strong>{summary.open_findings.toLocaleString()}</strong><small>Open or in progress</small></div></article>
          <article className="metric-card"><span className="metric-icon red"><AlertTriangle size={17} /></span><div><span className="metric-label">Critical &amp; high</span><strong>{summary.critical_high_findings.toLocaleString()}</strong><small>Open or in progress</small></div></article>
        </section>

        {summary.total_scans === 0 && <div className="empty-dashboard dashboard-empty">
          <div className="empty-visual" aria-hidden="true"><div className="orbit orbit-a" /><div className="orbit orbit-b" /><div className="orbit-core"><ShieldCheck size={29} strokeWidth={1.55} /></div><span className="orbit-node node-a"><Shield size={15} /></span><span className="orbit-node node-b"><Fingerprint size={15} /></span></div>
          <div className="empty-copy"><div className="empty-kicker"><span className="scope-dot" /> NO SCANS RECORDED</div><h2>Start with a target you’re authorized to assess.</h2><p>Your overview is drawn from stored scan results. Add an explicitly authorized target to start a genuine assessment; there are no sample findings or fabricated metrics.</p><Link to="/scan/new" className="button button-primary"><Plus size={16} /> Configure a new scan <ArrowRight size={15} /></Link></div>
        </div>}

        <section className="dashboard-panels">
          <article className="data-panel activity-panel">
            <div className="panel-title-row"><div><h2>Scan activity</h2><p>Persisted scans and findings by date</p></div><label className="period-select">Window<select aria-label="Activity time window" value={days} onChange={(event) => setDays(Number(event.target.value))}><option value={7}>7 days</option><option value={14}>14 days</option><option value={30}>30 days</option><option value={90}>90 days</option></select></label></div>
            {loading && !activity.length ? <div className="panel-loading"><span className="loading-dot" /> Loading activity…</div> : currentActivityTotal === 0 ? <div className="chart-empty"><Clock3 size={19} /><span>No scan activity in this time window.</span></div> : <div className="activity-chart"><ResponsiveContainer width="100%" height={220}><AreaChart data={activity} margin={{ top: 12, right: 8, bottom: 0, left: -20 }}><defs><linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.26} /><stop offset="95%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#27354a" strokeDasharray="3 5" vertical={false} /><XAxis dataKey="date" tickFormatter={dateLabel} tick={{ fill: '#8293aa', fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={24} /><YAxis allowDecimals={false} tick={{ fill: '#8293aa', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#111b2b', border: '1px solid #314059', borderRadius: 7, color: '#eaf3fb', fontSize: 11 }} labelFormatter={(label) => dateLabel(String(label))} /><Area type="monotone" dataKey="scans" name="Scans" stroke="#22d3ee" strokeWidth={2} fill="url(#scanFill)" /><Area type="monotone" dataKey="findings" name="Findings" stroke="#8b5cf6" strokeWidth={1.6} fill="transparent" /></AreaChart></ResponsiveContainer></div>}
            <div className="chart-legend"><span><i className="legend-dot cyan-dot" /> Scans</span><span><i className="legend-dot violet-dot" /> Findings</span><button className="icon-button" type="button" onClick={() => void load()} aria-label="Refresh dashboard"><RefreshCw size={14} /></button></div>
          </article>
          <article className="data-panel severity-panel">
            <div className="panel-title-row"><div><h2>Finding severity</h2><p>Active and accepted-risk findings</p></div><Link to="/findings" className="text-link">Details <ArrowRight size={13} /></Link></div>
            {totalActive === 0 ? <div className="chart-empty severity-empty"><Bug size={19} /><span>No active findings are recorded.</span></div> : <div className="severity-content"><div className="severity-donut"><ResponsiveContainer width="100%" height={185}><PieChart><Pie data={severityData} dataKey="value" nameKey="label" innerRadius={54} outerRadius={76} paddingAngle={2} stroke="none">{severityData.map((item) => <Cell key={item.key} fill={severityColors[item.key]} />)}</Pie><Tooltip contentStyle={{ background: '#111b2b', border: '1px solid #314059', borderRadius: 7, color: '#eaf3fb', fontSize: 11 }} /></PieChart></ResponsiveContainer><div className="donut-total"><strong>{totalActive}</strong><small>findings</small></div></div><ul className="severity-legend">{severityData.map((item) => <li key={item.key}><span><i style={{ backgroundColor: severityColors[item.key] }} />{item.label}</span><b>{item.value}</b></li>)}</ul></div>}
          </article>
        </section>

        <section className="dashboard-panels recent-panels">
          <article className="data-panel">
            <div className="panel-title-row"><div><h2>Recent scans</h2><p>Persisted runs · filter, sort and page through your scan history</p></div><Link to="/scans" className="text-link">Full history <ArrowRight size={13} /></Link></div>
            <form className="dashboard-scan-tools" onSubmit={submitRecentSearch}>
              <label className="sr-only" htmlFor="dashboard-scan-search">Search scan name, target, URL or ID</label>
              <input id="dashboard-scan-search" type="search" value={recentSearchDraft} onChange={(event) => setRecentSearchDraft(event.target.value)} placeholder="Search scan, target, URL or ID" />
              <button className="button button-secondary" type="submit">Search</button>
              <label className="period-select">Sort
                <select aria-label="Sort recent scans" value={`${recentSort}:${recentDirection}`} onChange={(event) => { const [nextSort, nextDirection] = event.target.value.split(':'); setRecentPage(1); setRecentSort(nextSort as typeof recentSort); setRecentDirection(nextDirection as typeof recentDirection); }}>
                  <option value="started_at:desc">Newest first</option><option value="started_at:asc">Oldest first</option><option value="findings_count:desc">Most findings</option><option value="findings_count:asc">Fewest findings</option>
                </select>
              </label>
            </form>
            {recentError && <div className="form-alert page-alert" role="alert"><span>{recentError}</span><button className="text-button" type="button" onClick={() => void loadRecentScans()}>Retry</button></div>}
            {recentLoading ? <div className="data-state" role="status"><span className="loading-dot" /> Loading scan history…</div>
              : recentScans.length === 0 ? <div className="inline-empty">{recentQuery ? 'No scans match this search.' : summary.total_scans > 0 ? 'No visible scans in default history; check archived records in Full history.' : 'No scans are recorded yet.'}</div>
                : <>
                  <div className="data-table-wrap dashboard-scan-table"><table className="data-table">
                    <caption className="sr-only">Recent scans loaded from the owner-scoped scan history API</caption>
                    <thead><tr><th scope="col">Scan</th><th scope="col">Target / profile</th><th scope="col">Status</th><th scope="col">Started</th><th scope="col">Duration</th><th scope="col">Findings</th></tr></thead>
                    <tbody>{recentScans.map((scan) => <tr key={scan.id}>
                      <th scope="row"><Link to={`/scans/${encodeURIComponent(scan.id)}`} className="data-link">{scan.name}</Link><small className="table-secondary code-id">{scan.id}</small></th>
                      <td>{scan.target_name}<small className="table-secondary">{scan.profile}</small></td>
                      <td><span className={`status-badge status-${scan.status}`}>{scan.status.replace('_', ' ')}</span></td>
                      <td>{dateTime(scan.started_at)}</td><td>{durationLabel(scan.duration_seconds)}</td><td>{scan.findings_count}</td>
                    </tr>)}</tbody>
                  </table></div>
                  <div className="pagination"><span>Showing {(recentPage - 1) * 5 + 1}–{Math.min(recentPage * 5, recentTotal)} of {recentTotal}</span><div className="pagination-actions"><button className="button button-secondary" type="button" disabled={recentPage <= 1} onClick={() => setRecentPage((value) => value - 1)}>Previous</button><span aria-current="page">Page {recentPage} of {Math.max(1, Math.ceil(recentTotal / 5))}</span><button className="button button-secondary" type="button" disabled={recentPage >= Math.max(1, Math.ceil(recentTotal / 5))} onClick={() => setRecentPage((value) => value + 1)}>Next</button></div></div>
                </>}
          </article>
          <article className="data-panel"><div className="panel-title-row"><div><h2>Recent findings</h2><p>Latest evidence from completed checks</p></div><Link to="/findings" className="text-link">All findings <ArrowRight size={13} /></Link></div>{summary.recent_findings.length ? <div className="recent-list">{summary.recent_findings.map((finding) => <Link className="recent-row finding-row" to={`/findings/${finding.id}`} key={finding.id}><span className={`severity-marker severity-${finding.severity}`} /><span className="recent-main"><strong>{finding.title}</strong><small>{finding.target_name} · {dateTime(finding.detected_at)}</small></span><span className={`severity-badge severity-${finding.severity}`}>{severityLabels[finding.severity]}</span></Link>)}</div> : <div className="inline-empty">No findings are recorded yet.</div>}</article>
        </section>
      </>}
      <div className="dashboard-disclaimer"><ShieldCheck size={14} /><span>Observed results are limited to completed checks within each explicitly authorized scope. No result is a guarantee of security.</span></div>
    </div>
  );
}
