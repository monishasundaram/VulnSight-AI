import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Ban, CheckCircle2, CircleAlert, Clock3, ExternalLink, RefreshCw, ShieldCheck } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { apiRequest, userFacingError } from '../services/api';

type ScanEvent = {
  id: string | number;
  stage: string;
  event_type: string;
  message: string;
  check_key?: string | null;
  created_at?: string | null;
};

type Scan = {
  id: string | number;
  target_id: string | number;
  target_name: string;
  target_url: string;
  name: string;
  description?: string;
  profile: 'quick' | 'standard' | 'advanced' | string;
  status: string;
  stage: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  error_summary?: string | null;
  cancel_requested?: boolean;
  checks_total: number;
  checks_completed: number;
  progress_percent: number;
  findings_count: number;
  limitations: string[];
  events?: ScanEvent[];
};

type Finding = {
  id: string | number;
  title: string;
  category: string;
  severity: string;
  affected_url?: string | null;
  description: string;
  evidence?: string | null;
  remediation?: string | null;
  confidence?: string | number | null;
  status?: string | null;
};
type RawFinding = Omit<Finding, 'evidence'> & { evidence?: unknown };

const activeStatuses = new Set(['queued', 'running']);

function isActiveStatus(status: string) {
  return activeStatuses.has(status);
}

function formatDate(value?: string | null) {
  if (!value) return 'Not recorded';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatEvidence(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value, null, 2) ?? String(value); }
  catch { return String(value); }
}

function severityClass(severity: string) {
  return `severity-badge severity-${severity.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
}

export default function ScanProgress() {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [canceling, setCanceling] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const requestGeneration = useRef(0);

  useEffect(() => {
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    if (!scanId) {
      setError('This scan URL does not include a scan ID.');
      setLoading(false);
      return;
    }
    if (canceling) return;
    const currentScanId = scanId;
    const controller = new AbortController();
    let active = true;
    let timer: number | undefined;

    async function loadFindings(id: string) {
      try {
        const result = await apiRequest<{ items: RawFinding[]; total: number }>(`/api/scans/${encodeURIComponent(id)}/findings`, { signal: controller.signal });
        if (!active || requestGeneration.current !== generation) return;
        setFindings((result.items || []).map((finding) => ({ ...finding, evidence: formatEvidence(finding.evidence) })));
        setFindingsTotal(result.total ?? result.items?.length ?? 0);
        setFindingsError(null);
      } catch (reason) {
        if (!active || requestGeneration.current !== generation || (reason instanceof DOMException && reason.name === 'AbortError')) return;
        setFindingsError(userFacingError(reason, 'Findings could not be loaded.'));
      }
    }

    async function poll() {
      try {
        const next = await apiRequest<Scan>(`/api/scans/${encodeURIComponent(currentScanId)}`, { signal: controller.signal });
        if (!active || requestGeneration.current !== generation) return;
        setScan(next);
        setError(null);
        setLoading(false);
        if (isActiveStatus(next.status)) {
          timer = window.setTimeout(() => void poll(), 1000);
        } else {
          await loadFindings(currentScanId);
        }
      } catch (reason) {
        if (!active || requestGeneration.current !== generation || (reason instanceof DOMException && reason.name === 'AbortError')) return;
        setError(userFacingError(reason, 'Scan progress could not be loaded.'));
        setLoading(false);
      }
    }

    void poll();
    return () => {
      active = false;
      controller.abort();
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [scanId, canceling, refreshNonce]);

  async function cancelScan() {
    if (!scanId || !scan || !isActiveStatus(scan.status) || canceling) return;
    if (!window.confirm('Cancel this active scan? No further requests will be sent after the active request closes.')) return;
    setCanceling(true);
    setError(null);
    try {
      await apiRequest<Scan>(`/api/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' });
      const refreshed = await apiRequest<Scan>(`/api/scans/${encodeURIComponent(scanId)}`);
      setScan(refreshed);
    } catch (reason) {
      setError(userFacingError(reason, 'The scan could not be cancelled.'));
    } finally {
      setCanceling(false);
    }
  }

  if (loading && !scan) return <section className="scan-progress"><div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> SCAN PROGRESS</div><div className="target-state" role="status" aria-live="polite"><span className="loading-dot" /> Loading scan progress…</div></section>;

  return <section className="scan-progress">
    <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> SCAN PROGRESS</div>
    <div className="welcome-row"><div><h1>{scan?.name || 'Scan progress'}</h1><p className="page-subtitle">Backend-reported progress and persisted evidence for this assessment.</p></div><Link className="button button-secondary" to="/scans"><ArrowLeft size={15} /> Back to scans</Link></div>
    {error && <div className="form-alert page-alert" role="alert" aria-live="assertive">{error}<button className="text-button" type="button" onClick={() => setRefreshNonce((value) => value + 1)}>Retry</button></div>}
    {!scan ? <div className="target-empty"><CircleAlert size={25} /><h2>Scan progress unavailable</h2><p>There is no scan data to display yet.</p></div> : <>
      <div className="scan-progress-summary">
        <div className="scan-progress-heading"><div><span className="page-eyebrow"><span className="eyebrow-line" /> {scan.profile.toUpperCase()} PROFILE</span><h2>{scan.target_name}</h2><a href={scan.target_url} target="_blank" rel="noopener noreferrer">{scan.target_url} <ExternalLink size={13} /></a></div><span className={`status-badge status-${scan.status}`}>{scan.status}</span></div>
        <div className="scan-progress-meta"><div><span>Stage</span><strong>{scan.stage}</strong></div><div><span>Checks</span><strong>{scan.checks_completed} / {scan.checks_total}</strong></div><div><span>Started</span><strong>{formatDate(scan.started_at)}</strong></div></div>
        <div className="progress-track" aria-live="polite" aria-label={`Backend-reported scan progress: ${scan.progress_percent}%`}><progress className="progress-bar" max={100} value={scan.progress_percent}>{scan.progress_percent}%</progress><strong>{scan.progress_percent}%</strong></div>
        {isActiveStatus(scan.status) && <button className="button button-secondary cancel-scan-button" type="button" onClick={() => void cancelScan()} disabled={canceling}>{canceling ? <><span className="loading-dot" /> Cancelling…</> : <><Ban size={15} /> Cancel scan</>}</button>}
        {scan.error_summary && <div className="form-alert" role="alert">{scan.error_summary}</div>}
      </div>
      <div className="scan-progress-grid">
        <section className="info-panel scan-scope-panel" aria-labelledby="scan-scope-title"><div className="panel-heading"><span className="panel-icon cyan"><ShieldCheck size={16} /></span><div><h2 id="scan-scope-title">Authorized scope and limitations</h2><p>Recorded with this scan; no scope is inferred in the browser.</p></div></div><dl className="target-meta"><div><dt>Target URL</dt><dd><a href={scan.target_url} target="_blank" rel="noopener noreferrer">{scan.target_url}</a></dd></div><div><dt>Findings returned</dt><dd>{scan.findings_count}</dd></div></dl><ul className="limitation-list">{scan.limitations.map((limitation, index) => <li key={`${limitation}-${index}`}>{limitation}</li>)}</ul></section>
        <section className="info-panel event-panel" aria-labelledby="event-title"><div className="panel-heading"><span className="panel-icon violet"><Clock3 size={16} /></span><div><h2 id="event-title">Persisted events</h2><p>Events are read from the scan record.</p></div></div>{scan.events?.length ? <ol className="event-timeline">{scan.events.map((event) => <li key={String(event.id)}><span className="event-marker" aria-hidden="true" /> <div><div className="event-heading"><strong>{event.stage}</strong><time dateTime={event.created_at || undefined}>{formatDate(event.created_at)}</time></div><p>{event.message}</p>{event.check_key && <small>{event.check_key}</small>}</div></li>)}</ol> : <p className="empty-note">No persisted events have been recorded yet.</p>}</section>
      </div>
      <section className="findings-section" aria-labelledby="findings-title"><div className="panel-heading"><span className="panel-icon cyan"><CheckCircle2 size={16} /></span><div><h2 id="findings-title">Findings</h2><p>Only findings returned by the scan API are shown.</p></div><span className="status-badge">{findingsTotal}</span></div>{findingsError && <div className="form-alert" role="alert">{findingsError}<button className="text-button" type="button" onClick={() => setRefreshNonce((value) => value + 1)}><RefreshCw size={13} /> Retry</button></div>}{findings.length === 0 && !findingsError ? <p className="empty-note">No findings were returned for this scan.</p> : <div className="finding-list">{findings.map((finding) => <article className="finding-card" key={String(finding.id)}><div className="finding-card-heading"><h3>{finding.title}</h3><span className={severityClass(finding.severity)}>{finding.severity}</span></div><p className="finding-category">{finding.category}{finding.affected_url ? <> · <a href={finding.affected_url} target="_blank" rel="noopener noreferrer">{finding.affected_url}</a></> : null}</p><p>{finding.description}</p>{finding.evidence && <div className="finding-evidence"><strong>Evidence</strong><p>{finding.evidence}</p></div>}{finding.remediation && <div className="finding-remediation"><strong>Remediation</strong><p>{finding.remediation}</p></div>}</article>)}</div>}</section>
    </>}
  </section>;
}
