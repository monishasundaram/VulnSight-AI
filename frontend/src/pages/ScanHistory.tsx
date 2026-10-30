import { useEffect, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Archive, RotateCcw } from 'lucide-react';
import { apiRequest, userFacingError } from '../services/api';

type Scan = {
  id: string;
  target_id?: string;
  target_name?: string;
  target_url?: string;
  name?: string;
  profile?: string;
  status?: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  findings_count?: number;
  archived_at?: string | null;
};
type TargetOption = { id: string; name: string; enabled?: boolean };
type ScanListResponse = { items?: Scan[]; total?: number; page?: number; page_size?: number };
type TargetListResponse = { items?: TargetOption[] };
const PAGE_SIZE = 20;
const statuses = ['', 'queued', 'running', 'completed', 'failed', 'cancelled'] as const;
const terminal = new Set(['completed', 'failed', 'cancelled']);

function displayDate(value?: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function formatDuration(value?: number | null) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  if (value < 60) return `${value.toFixed(1)} s`;
  const minutes = Math.floor(value / 60);
  return `${minutes}m ${Math.floor(value % 60)}s`;
}
function label(value?: string) { return value ? value.replace(/_/g, ' ') : 'Unknown'; }

export default function ScanHistory() {
  const [searchParams] = useSearchParams();
  const [items, setItems] = useState<Scan[]>([]);
  const [targets, setTargets] = useState<TargetOption[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [targetId, setTargetId] = useState(() => searchParams.get('target_id') || '');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [status, setStatus] = useState('');
  const [sort, setSort] = useState<'started_at' | 'findings_count'>('started_at');
  const [direction, setDirection] = useState<'asc' | 'desc'>('desc');
  const [includeArchived, setIncludeArchived] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function loadScans() {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE), sort, direction });
    if (status) params.set('status', status);
    if (query) params.set('query', query);
    if (targetId) params.set('target_id', targetId);
    if (dateFrom) params.set('date_from', dateFrom);
    if (dateTo) params.set('date_to', dateTo);
    if (includeArchived) params.set('include_archived', 'true');
    try {
      const response = await apiRequest<ScanListResponse>(`/api/scans?${params.toString()}`);
      setItems(Array.isArray(response.items) ? response.items : []);
      setTotal(typeof response.total === 'number' ? response.total : 0);
    } catch (reason) {
      setItems([]);
      setTotal(0);
      setError(userFacingError(reason, 'Scan history could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let alive = true;
    apiRequest<TargetListResponse>('/api/targets?page=1&page_size=100&include_disabled=true')
      .then((result) => { if (alive) setTargets(Array.isArray(result.items) ? result.items : []); })
      .catch((reason: unknown) => { if (alive) setError(userFacingError(reason, 'Target filters could not be loaded.')); });
    return () => { alive = false; };
  }, []);
  useEffect(() => { void loadScans(); }, [page, query, targetId, dateFrom, dateTo, status, sort, direction, includeArchived]);

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(1);
    setQuery(search.trim());
  }
  function changeFilter(setter: (value: string) => void, value: string) {
    setPage(1);
    setter(value);
  }

  async function changeArchive(scan: Scan) {
    const isArchived = Boolean(scan.archived_at);
    const warning = isArchived
      ? `Restore “${scan.name || 'this scan'}” to the default history? Its findings, reports and audit history have been retained.`
      : `Archive “${scan.name || 'this scan'}” from the default history? This does not delete its findings, reports, events or audit history. You can show archived scans and restore it later.`;
    if (!window.confirm(warning)) return;
    const scanId = String(scan.id);
    setBusyId(scanId);
    setError(null);
    try {
      await apiRequest(`/api/scans/${encodeURIComponent(scanId)}${isArchived ? '/restore' : ''}`, {
        method: isArchived ? 'POST' : 'DELETE',
      });
      await loadScans();
    } catch (reason) {
      setError(userFacingError(reason, isArchived ? 'Unable to restore this scan.' : 'Unable to archive this scan.'));
    } finally {
      setBusyId(null);
    }
  }

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const filtersActive = Boolean(query || targetId || dateFrom || dateTo || status);

  return (
    <section className="scan-history-page">
      <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> SCAN HISTORY</div>
      <div className="welcome-row">
        <div><h1>Scan history</h1><p className="page-subtitle">Review persisted assessment runs and their recorded outcomes. Archiving hides a terminal scan from the default list; its evidence and audit trail remain available.</p></div>
      </div>

      <div className="table-toolbar" role="search" aria-label="Filter scan history">
        <form className="table-search" onSubmit={submitSearch}>
          <label htmlFor="scan-search">Search scans and targets</label>
          <input id="scan-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search name, target, URL or ID" />
          <button className="button button-secondary" type="submit">Search</button>
        </form>
        <label className="table-filter">Target
          <select value={targetId} onChange={(event) => changeFilter(setTargetId, event.target.value)}><option value="">All targets</option>{targets.map((target) => <option key={target.id} value={target.id}>{target.name}{target.enabled === false ? ' (disabled)' : ''}</option>)}</select>
        </label>
        <label className="table-filter">Status
          <select value={status} onChange={(event) => changeFilter(setStatus, event.target.value)}>{statuses.map((value) => <option key={value} value={value}>{value ? label(value) : 'All statuses'}</option>)}</select>
        </label>
        <label className="table-filter">From<input aria-label="Start date from" type="date" value={dateFrom} onChange={(event) => changeFilter(setDateFrom, event.target.value)} /></label>
        <label className="table-filter">To<input aria-label="Start date to" type="date" value={dateTo} onChange={(event) => changeFilter(setDateTo, event.target.value)} /></label>
        <label className="table-filter">Sort
          <select aria-label="Sort scan history" value={`${sort}:${direction}`} onChange={(event) => { const [nextSort, nextDirection] = event.target.value.split(':'); setPage(1); setSort(nextSort as typeof sort); setDirection(nextDirection as typeof direction); }}><option value="started_at:desc">Newest first</option><option value="started_at:asc">Oldest first</option><option value="findings_count:desc">Most findings</option><option value="findings_count:asc">Fewest findings</option></select>
        </label>
        <label className="archive-filter"><input type="checkbox" checked={includeArchived} onChange={(event) => { setPage(1); setIncludeArchived(event.target.checked); }} /> Include archived</label>
      </div>

      {error && <div className="form-alert page-alert" role="alert"><span>{error}</span><button className="text-button" type="button" onClick={() => void loadScans()}>Retry</button></div>}
      {loading ? <div className="data-state" role="status"><span className="loading-dot" /> Loading scan history…</div>
        : items.length === 0 ? <div className="data-empty"><h2>{filtersActive ? 'No scans match these filters' : includeArchived ? 'No archived scans recorded' : 'No scans recorded'}</h2><p>{filtersActive ? 'Try a different search, target, date range or status filter.' : 'Completed and in-progress assessments will appear here once they are recorded. All history is loaded from your SQLite workspace.'}</p></div>
          : <>
            <div className="data-table-wrap"><table className="data-table">
              <caption className="sr-only">Persisted scan history</caption>
              <thead><tr><th scope="col">Scan ID / name</th><th scope="col">Target</th><th scope="col">Profile</th><th scope="col">Status</th><th scope="col">Started</th><th scope="col">Completed</th><th scope="col">Duration</th><th scope="col">Findings</th><th scope="col">Actions</th></tr></thead>
              <tbody>{items.map((scan) => {
                const canArchive = terminal.has(scan.status || '');
                const scanId = String(scan.id);
                return <tr key={scanId}>
                  <th scope="row"><Link to={`/scans/${encodeURIComponent(scanId)}`} className="data-link">{scan.name || `Scan ${scanId}`}</Link><small className="table-secondary code-id">{scanId}</small>{scan.archived_at && <small className="table-secondary">Archived {displayDate(scan.archived_at)}</small>}</th>
                  <td>{scan.target_name || scan.target_url || 'Unavailable target'}</td><td>{label(scan.profile)}</td>
                  <td><span className={`status-badge status-${scan.status || 'unknown'}`}>{label(scan.status)}</span></td>
                  <td>{displayDate(scan.started_at)}</td><td>{displayDate(scan.completed_at)}</td><td>{formatDuration(scan.duration_seconds)}</td>
                  <td>{typeof scan.findings_count === 'number' ? scan.findings_count : '—'}</td>
                  <td className="history-actions">{terminal.has(scan.status || '') && <Link to={`/reports/${encodeURIComponent(scanId)}`} className="text-link">Report</Link>}{canArchive ? <button className="button button-quiet archive-action" type="button" disabled={busyId === scanId} onClick={() => void changeArchive(scan)} aria-label={scan.archived_at ? `Restore ${scan.name || 'scan'}` : `Archive ${scan.name || 'scan'}`}>{scan.archived_at ? <RotateCcw size={13} /> : <Archive size={13} />}{busyId === scanId ? ' Saving…' : scan.archived_at ? ' Restore' : ' Archive'}</button> : <span className="table-secondary">Active</span>}</td>
                </tr>;
              })}</tbody>
            </table></div>
            <nav className="pagination" aria-label="Scan history pages"><span>Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}</span><div className="pagination-actions"><button className="button button-secondary" type="button" disabled={page <= 1} onClick={() => setPage((current) => current - 1)}>Previous</button><span aria-current="page">Page {page} of {pageCount}</span><button className="button button-secondary" type="button" disabled={page >= pageCount} onClick={() => setPage((current) => current + 1)}>Next</button></div></nav>
          </>}
    </section>
  );
}
