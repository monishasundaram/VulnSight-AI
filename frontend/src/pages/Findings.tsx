import { useEffect, useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { apiRequest, userFacingError } from '../services/api';

type Finding = {
  id: string;
  title?: string;
  severity?: string;
  status?: string;
  target_name?: string;
  scan_name?: string;
  affected_url?: string;
  detected_at?: string | null;
};
type ScanOption = { id: string; name?: string; target_name?: string };
type FindingListResponse = { items?: Finding[]; total?: number; page?: number; page_size?: number };
type FilterOptions = { categories?: string[]; scans?: ScanOption[] };
const PAGE_SIZE = 25;
const severities = ['', 'critical', 'high', 'medium', 'low', 'informational'] as const;
const statuses = ['', 'open', 'in_progress', 'resolved', 'accepted_risk'] as const;

function label(value?: string) { return value ? value.replace(/_/g, ' ') : 'Unknown'; }
function displayDate(value?: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function Findings() {
  const [searchParams] = useSearchParams();
  const [items, setItems] = useState<Finding[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [scans, setScans] = useState<ScanOption[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [category, setCategory] = useState('');
  const [scanId, setScanId] = useState('');
  const [targetId, setTargetId] = useState(() => searchParams.get('target_id') || '');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    apiRequest<FilterOptions>('/api/findings/filters')
      .then((result) => {
        if (!alive) return;
        setCategories(Array.isArray(result.categories) ? result.categories : []);
        setScans(Array.isArray(result.scans) ? result.scans : []);
      })
      .catch((reason: unknown) => { if (alive) setError(userFacingError(reason, 'Finding filter options could not be loaded.')); });
    return () => { alive = false; };
  }, []);

  async function loadFindings() {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (severity) params.set('severity', severity);
    if (status) params.set('status', status);
    if (category) params.set('category', category);
    if (scanId) params.set('scan_id', scanId);
    if (targetId) params.set('target_id', targetId);
    if (query) params.set('query', query);
    try {
      const response = await apiRequest<FindingListResponse>(`/api/findings?${params.toString()}`);
      setItems(Array.isArray(response.items) ? response.items : []);
      setTotal(typeof response.total === 'number' ? response.total : 0);
    } catch (reason) {
      setItems([]);
      setTotal(0);
      setError(userFacingError(reason, 'Vulnerabilities could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void loadFindings(); }, [page, query, severity, status, category, scanId, targetId]);
  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPage(1);
    setQuery(search.trim());
  }
  function changeFilter(setter: (value: string) => void, value: string) {
    setPage(1);
    setter(value);
  }
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const filtersActive = Boolean(query || severity || status || category || scanId || targetId);

  return (
    <section className="findings-page">
      <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> VULNERABILITIES</div>
      <div className="welcome-row"><div><h1>Vulnerabilities</h1><p className="page-subtitle">Investigate evidence-backed findings from authorized scans.</p></div></div>
      {targetId && <div className="target-filter-note" role="status">Showing findings for target <code>{targetId}</code><button className="text-button" type="button" onClick={() => setTargetId('')}>Clear target filter</button></div>}
      <div className="table-toolbar" role="search" aria-label="Filter vulnerabilities">
        <form className="table-search" onSubmit={submitSearch}>
          <label htmlFor="finding-search">Search findings</label><input id="finding-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title or description" /><button className="button button-secondary" type="submit">Search</button>
        </form>
        <label className="table-filter">Severity<select value={severity} onChange={(event) => changeFilter(setSeverity, event.target.value)}>{severities.map((value) => <option key={value} value={value}>{value ? label(value) : 'All severities'}</option>)}</select></label>
        <label className="table-filter">Status<select value={status} onChange={(event) => changeFilter(setStatus, event.target.value)}>{statuses.map((value) => <option key={value} value={value}>{value ? label(value) : 'All statuses'}</option>)}</select></label>
        <label className="table-filter">Category<select value={category} onChange={(event) => changeFilter(setCategory, event.target.value)}><option value="">All categories</option>{categories.map((value) => <option key={value} value={value}>{label(value)}</option>)}</select></label>
        <label className="table-filter">Scan<select value={scanId} onChange={(event) => changeFilter(setScanId, event.target.value)}><option value="">All scans</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{scan.name || scan.id} · {scan.target_name || 'Target'}</option>)}</select></label>
      </div>
      {error && <div className="form-alert page-alert" role="alert"><span>{error}</span><button className="text-button" type="button" onClick={() => void loadFindings()}>Retry</button></div>}
      {loading ? <div className="data-state" role="status"><span className="loading-dot" /> Loading vulnerabilities…</div>
        : items.length === 0 ? <div className="data-empty"><h2>{filtersActive ? 'No vulnerabilities match these filters' : 'No vulnerabilities recorded'}</h2><p>{filtersActive ? 'Try another query, severity, status, category or scan.' : 'Findings from completed checks will appear here.'}</p></div>
          : <>
            <div className="data-table-wrap"><table className="data-table">
              <caption className="sr-only">Recorded vulnerabilities</caption>
              <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Target / scan</th><th scope="col">Detected</th></tr></thead>
              <tbody>{items.map((finding) => <tr key={finding.id}>
                <th scope="row"><Link className="data-link" to={`/findings/${encodeURIComponent(finding.id)}`}>{finding.title || `Finding ${finding.id}`}</Link><small className="table-secondary">{finding.affected_url || 'Affected URL unavailable'}</small></th>
                <td><span className={`severity-badge severity-${finding.severity || 'unknown'}`}>{label(finding.severity)}</span></td>
                <td><span className={`status-badge status-${finding.status || 'unknown'}`}>{label(finding.status)}</span></td>
                <td><span>{finding.target_name || 'Unavailable target'}</span><small className="table-secondary">{finding.scan_name || 'Unavailable scan'}</small></td>
                <td>{displayDate(finding.detected_at)}</td>
              </tr>)}</tbody>
            </table></div>
            <nav className="pagination" aria-label="Vulnerability pages"><span>Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}</span><div className="pagination-actions"><button className="button button-secondary" type="button" disabled={page <= 1} onClick={() => setPage((current) => current - 1)}>Previous</button><span aria-current="page">Page {page} of {pageCount}</span><button className="button button-secondary" type="button" disabled={page >= pageCount} onClick={() => setPage((current) => current + 1)}>Next</button></div></nav>
          </>}
    </section>
  );
}
