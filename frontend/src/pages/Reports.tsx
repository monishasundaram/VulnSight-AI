import { useCallback, useEffect, useState } from 'react';
import { Download, FileJson2, FileText, RefreshCw } from 'lucide-react';
import { useParams } from 'react-router-dom';
import { apiRequest, userFacingError } from '../services/api';

type ReportFormat = 'pdf' | 'json';
type ReportRecord = {
  id: string | number; scan_id: string | number; format: ReportFormat; generated_at?: string; sha256?: string;
  target_name?: string; scan_name?: string; profile?: string; status?: string; download_url?: string;
};
type EligibleScan = {
  id: string | number; name?: string; target_name?: string; target_url?: string; profile?: string; status?: string;
  started_at?: string | null; completed_at?: string | null; findings_count?: number;
};
type PageResponse<T> = { items?: T[]; total?: number; page?: number; page_size?: number };
type ReportListResponse = { items?: ReportRecord[]; total?: number };
type GeneratedReport = { download_url: string; filename?: string; format: ReportFormat; scan_id: string | number };
type ReportPreview = {
  report_title?: string; generated_at?: string; executive_summary?: string; finding_count?: number;
  severity_counts?: Record<string, number>; scan?: { id?: string | number; name?: string; profile?: string; status?: string; started_at?: string; completed_at?: string | null };
  authorized_scope?: { target_name?: string; base_url?: string }; limitations?: string[];
  findings?: Array<{ id?: string | number; title?: string; severity?: string; status?: string; affected_url?: string }>;
};
type UserSettings = { preferences: { default_report_format: ReportFormat } };

const PAGE_SIZE = 20;
function label(value?: string) { return value ? value.replace(/_/g, ' ') : 'Unknown'; }
function displayDate(value?: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function keyFor(scanId: string | number, format: ReportFormat) { return `${String(scanId)}:${format}`; }
function safeDownloadUrl(value: string) {
  try {
    const parsed = new URL(value, window.location.origin);
    return parsed.origin === window.location.origin && parsed.pathname.startsWith('/api/') ? parsed.href : null;
  } catch { return null; }
}
function filenameFromDisposition(header: string | null) {
  if (!header) return null;
  const utf = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf) { try { return decodeURIComponent(utf[1]); } catch { return null; } }
  const plain = header.match(/filename="?([^";]+)"?/i);
  return plain?.[1] || null;
}

export default function Reports() {
  const { scanId: routeScanId } = useParams<{ scanId?: string }>();
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [eligibleScans, setEligibleScans] = useState<EligibleScan[]>([]);
  const [eligibleTotal, setEligibleTotal] = useState(0);
  const [eligiblePage, setEligiblePage] = useState(1);
  const [defaultFormat, setDefaultFormat] = useState<ReportFormat>('pdf');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(routeScanId || null);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [generated, setGenerated] = useState<Record<string, GeneratedReport>>({});
  const [generating, setGenerating] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<'idle' | 'copied'>('idle');
  const [copyError, setCopyError] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    const params = new URLSearchParams({ page: String(eligiblePage), page_size: String(PAGE_SIZE) });
    try {
      const [reportResult, scanResult, settingsResult] = await Promise.all([
        apiRequest<ReportListResponse>('/api/reports'),
        apiRequest<PageResponse<EligibleScan>>(`/api/reports/eligible-scans?${params.toString()}`),
        apiRequest<UserSettings>('/api/settings'),
      ]);
      setReports(Array.isArray(reportResult.items) ? reportResult.items : []);
      setEligibleScans(Array.isArray(scanResult.items) ? scanResult.items : []);
      setEligibleTotal(typeof scanResult.total === 'number' ? scanResult.total : 0);
      if (settingsResult.preferences.default_report_format === 'pdf' || settingsResult.preferences.default_report_format === 'json') {
        setDefaultFormat(settingsResult.preferences.default_report_format);
      }
    } catch (reason) {
      setError(userFacingError(reason, 'Reports and eligible scans could not be loaded.'));
      setReports([]);
      setEligibleScans([]);
      setEligibleTotal(0);
    } finally { setLoading(false); }
  }, [eligiblePage]);
  useEffect(() => { void loadReports(); }, [loadReports]);
  useEffect(() => { if (routeScanId) setSelectedScanId(routeScanId); }, [routeScanId]);

  useEffect(() => {
    setCopyStatus('idle');
    setCopyError(null);
    if (!selectedScanId) { setPreview(null); setPreviewError(null); return; }
    let active = true;
    setPreviewLoading(true);
    setPreviewError(null);
    apiRequest<ReportPreview>(`/api/reports/${encodeURIComponent(selectedScanId)}`)
      .then((response) => { if (active) setPreview(response); })
      .catch((reason) => { if (active) { setPreview(null); setPreviewError(userFacingError(reason, 'The report preview could not be loaded.')); } })
      .finally(() => { if (active) setPreviewLoading(false); });
    return () => { active = false; };
  }, [selectedScanId]);

  async function generateReport(scanId: string | number, format: ReportFormat) {
    const generationKey = keyFor(scanId, format);
    setGenerating(generationKey);
    setDownloadError(null);
    try {
      const response = await apiRequest<GeneratedReport>(`/api/reports/${encodeURIComponent(String(scanId))}`, {
        method: 'POST', body: JSON.stringify({ format }),
      });
      if (!response.download_url) throw new Error('The server did not return a download URL.');
      setGenerated((current) => ({ ...current, [generationKey]: { ...response, format, scan_id: scanId } }));
      setSelectedScanId(String(scanId));
      await loadReports();
    } catch (reason) { setDownloadError(userFacingError(reason, 'The report could not be generated.')); }
    finally { setGenerating(null); }
  }

  async function downloadReport(report: GeneratedReport) {
    const url = safeDownloadUrl(report.download_url);
    if (!url) { setDownloadError('The server returned an invalid same-origin download URL.'); return; }
    setDownloadError(null);
    try {
      const response = await fetch(url, { credentials: 'include', redirect: 'error' });
      if (!response.ok) {
        let message = `Download failed (${response.status})`;
        try { const body = await response.json() as { detail?: unknown; message?: unknown }; if (typeof body.detail === 'string') message = body.detail; else if (typeof body.message === 'string') message = body.message; } catch { /* binary/error body */ }
        throw new Error(message);
      }
      const blob = await response.blob();
      const fallback = `vulnsight-scan-${report.scan_id}.${report.format}`;
      const filename = filenameFromDisposition(response.headers.get('Content-Disposition')) || report.filename || fallback;
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 1000);
    } catch (reason) { setDownloadError(reason instanceof Error ? reason.message : 'The report download failed.'); }
  }

  async function copyExecutiveSummary() {
    const text = preview?.executive_summary?.trim();
    setCopyError(null);
    setCopyStatus('idle');
    if (!text) {
      setCopyError('There is no executive summary to copy for this report.');
      return;
    }
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard access is unavailable in this browser context.');
      await navigator.clipboard.writeText(text);
      setCopyStatus('copied');
    } catch (reason) {
      setCopyError(userFacingError(reason, 'The executive summary could not be copied.'));
    }
  }

  function reportSource(scanId: string | number, format: ReportFormat, existingUrl?: string) {
    const generatedReport = generated[keyFor(scanId, format)];
    if (generatedReport) return generatedReport;
    return existingUrl ? { download_url: existingUrl, filename: `vulnsight-scan-${scanId}.${format}`, format, scan_id: scanId } : null;
  }

  const scanPageCount = Math.max(1, Math.ceil(eligibleTotal / PAGE_SIZE));
  return <section className="reports-page">
    <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> REPORTS</div>
    <div className="welcome-row"><div><h1>Reports</h1><p className="page-subtitle">Generate and download persisted PDF or JSON assessments from terminal scans.</p></div></div>
    {error && <div className="form-alert page-alert" role="alert"><span>{error}</span><button className="text-button" type="button" onClick={() => void loadReports()}>Retry</button></div>}
    {downloadError && <div className="form-alert page-alert" role="alert">{downloadError}</div>}
    {loading ? <div className="data-state" role="status"><span className="loading-dot" /> Loading report records and eligible scans…</div> : <>
      <section className="eligible-scans" aria-labelledby="eligible-scans-heading">
        <div className="panel-title-row"><div><h2 id="eligible-scans-heading">Generate from a saved scan</h2><p>Only persisted terminal scan records returned by the API are listed. Your default format is {defaultFormat.toUpperCase()}.</p></div><button className="icon-button" type="button" onClick={() => void loadReports()} aria-label="Refresh report records"><RefreshCw size={14} /></button></div>
        {eligibleScans.length === 0 ? <p className="empty-note">No completed, failed or cancelled scans are available for reporting on this page.</p> : <div className="eligible-scan-list">{eligibleScans.map((scan) => <article className="eligible-scan-row" key={String(scan.id)}><div className="eligible-scan-main"><strong>{scan.name || `Scan ${scan.id}`}</strong><small>{scan.target_name || scan.target_url || 'Unavailable target'} · {label(scan.profile)} · {label(scan.status)} · {displayDate(scan.completed_at || scan.started_at)}</small></div><span className="eligible-finding-count">{scan.findings_count ?? 0} findings</span><button className="button button-secondary" type="button" onClick={() => setSelectedScanId(String(scan.id))}>Preview</button>{(['pdf', 'json'] as const).map((format) => { const key = keyFor(scan.id, format); return <button className={`button ${format === defaultFormat ? 'button-primary' : 'button-secondary'}`} type="button" key={format} disabled={generating === key} onClick={() => void generateReport(scan.id, format)}>{generating === key ? 'Generating…' : format === 'pdf' ? <><FileText size={14} /> PDF{format === defaultFormat ? ' · default' : ''}</> : <><FileJson2 size={14} /> JSON{format === defaultFormat ? ' · default' : ''}</>}</button>; })}</article>)}</div>}
        {eligibleTotal > PAGE_SIZE && <nav className="pagination" aria-label="Eligible scans pages"><span>Showing {(eligiblePage - 1) * PAGE_SIZE + 1}–{Math.min(eligiblePage * PAGE_SIZE, eligibleTotal)} of {eligibleTotal} terminal scans</span><div className="pagination-actions"><button className="button button-secondary" type="button" disabled={eligiblePage <= 1} onClick={() => setEligiblePage((value) => value - 1)}>Previous</button><span>Page {eligiblePage} of {scanPageCount}</span><button className="button button-secondary" type="button" disabled={eligiblePage >= scanPageCount} onClick={() => setEligiblePage((value) => value + 1)}>Next</button></div></nav>}
      </section>

      <section className="report-list-section" aria-labelledby="saved-reports-heading"><div className="panel-title-row"><div><h2 id="saved-reports-heading">Saved report files</h2><p>Download links reference report files generated by the server.</p></div></div>
        {reports.length === 0 ? <div className="data-empty compact-empty"><h3>No reports recorded yet</h3><p>Choose PDF or JSON above to generate and persist a report from a saved scan.</p></div> : <div className="data-table-wrap"><table className="data-table"><caption className="sr-only">Persisted report records</caption><thead><tr><th scope="col">Target / scan</th><th scope="col">Format</th><th scope="col">Generated</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead><tbody>{reports.map((report) => { const item = reportSource(report.scan_id, report.format, report.download_url); const rowKey = keyFor(report.scan_id, report.format); return <tr key={String(report.id)}><th scope="row"><button className="link-button" type="button" onClick={() => setSelectedScanId(String(report.scan_id))}>{report.target_name || 'Unavailable target'}</button><small className="table-secondary">{report.scan_name || `Scan ${report.scan_id}`}</small></th><td><span className="format-badge">{report.format.toUpperCase()}</span></td><td>{displayDate(report.generated_at)}</td><td><span className={`status-badge status-${report.status || 'unknown'}`}>{label(report.status)}</span></td><td><div className="report-actions"><button className="button button-secondary" type="button" onClick={() => setSelectedScanId(String(report.scan_id))}>Preview</button><button className="button button-secondary" type="button" disabled={generating === rowKey} onClick={() => void generateReport(report.scan_id, report.format)}>{generating === rowKey ? 'Generating…' : 'Regenerate'}</button><button className="button button-primary" type="button" disabled={!item} onClick={() => item && void downloadReport(item)}><Download size={14} /> Download</button></div></td></tr>; })}</tbody></table></div>}
      </section>
    </>}

    {selectedScanId && <section className="report-preview" aria-live="polite"><div className="panel-heading"><div><h2>Report preview</h2><p>Preview fetched from the selected persisted scan.</p></div></div>{previewLoading ? <div className="data-state" role="status"><span className="loading-dot" /> Loading preview…</div> : previewError ? <div className="form-alert" role="alert">{previewError}</div> : preview ? <div className="report-preview-content"><h3>{preview.report_title || 'Security assessment report'}</h3><p>{preview.executive_summary || 'No executive summary recorded.'}</p><div className="report-summary-actions"><button className="button button-secondary" type="button" onClick={() => void copyExecutiveSummary()} disabled={!preview.executive_summary}><FileText size={14} />{copyStatus === 'copied' ? 'Copied' : 'Copy executive summary'}</button>{copyStatus === 'copied' && <span className="save-success" role="status">Executive summary copied.</span>}{copyError && <span className="form-alert" role="alert">{copyError}</span>}</div><dl className="report-meta"><div><dt>Target</dt><dd>{preview.authorized_scope?.target_name || 'Unavailable target'}</dd></div><div><dt>Scan</dt><dd>{preview.scan?.name || selectedScanId} · {label(preview.scan?.profile)} · {label(preview.scan?.status)}</dd></div><div><dt>Findings</dt><dd>{typeof preview.finding_count === 'number' ? preview.finding_count : '—'}</dd></div></dl>{preview.findings?.length ? <ul className="preview-findings">{preview.findings.map((item, index) => <li key={String(item.id || index)}><strong>{item.title || 'Untitled finding'}</strong><span className={`severity-badge severity-${item.severity || 'unknown'}`}>{label(item.severity)}</span><small>{label(item.status)} · {item.affected_url || 'URL unavailable'}</small></li>)}</ul> : <p>No findings are included in this preview.</p>}{preview.limitations?.length ? <details><summary>Assessment limitations</summary><ul>{preview.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details> : null}</div> : <p>No report preview is available for this scan.</p>}</section>}
  </section>;
}
