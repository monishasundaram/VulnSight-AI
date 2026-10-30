import { useCallback, useEffect, useState } from 'react';
import { Check, CircleAlert, Save, ShieldCheck, SlidersHorizontal } from 'lucide-react';
import { apiRequest, userFacingError } from '../services/api';

type SettingsResponse = {
  user: { id: string; email: string; role: string; created_at: string };
  preferences: { theme: 'dark' | 'light'; default_report_format: 'pdf' | 'json'; report_retention_days: 0 | 30 | 90 | 180 | 365 };
  scan_limits: {
    allowed_ports: number[]; max_requests_per_scan: number; max_redirects_per_request: number;
    request_timeout_seconds: number; max_response_bytes: number; max_concurrent_jobs: number;
    max_scan_duration_seconds: number; scan_rate_per_minute: number; max_targets_per_user: number;
  };
  security: { session_ttl_hours: number; cookie_secure: boolean; cookie_samesite: string; hsts_enabled: boolean };
  reports: { retention_days: number; cleanup_behavior: string; max_retention_days: number };
  integrations: { owasp_zap: { configured: boolean; active_scanning_enabled: boolean; message: string } };
  severity_policy: { overrides: Record<string, string>; configuration: string };
  api_version: string; environment: string;
};
type HealthResponse = { status: string; database: string; version: string };

export default function Settings() {
  const [data, setData] = useState<SettingsResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [format, setFormat] = useState<'pdf' | 'json'>('pdf');
  const [retention, setRetention] = useState<0 | 30 | 90 | 180 | 365>(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [result] = await Promise.all([
        apiRequest<SettingsResponse>('/api/settings'),
        apiRequest<HealthResponse>('/api/health').then(setHealth).catch(() => setHealth(null)),
      ]);
      setData(result);
      setTheme(result.preferences.theme);
      setFormat(result.preferences.default_report_format);
      setRetention(result.preferences.report_retention_days);
      document.documentElement.dataset.theme = result.preferences.theme;
    } catch (reason) {
      setError(userFacingError(reason, 'Settings could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function save() {
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const result = await apiRequest<SettingsResponse>('/api/settings', {
        method: 'PATCH', body: JSON.stringify({ theme, default_report_format: format, report_retention_days: retention }),
      });
      setData(result);
      setTheme(result.preferences.theme);
      setFormat(result.preferences.default_report_format);
      setRetention(result.preferences.report_retention_days);
      document.documentElement.dataset.theme = result.preferences.theme;
      setSaved(true);
    } catch (reason) {
      setError(userFacingError(reason, 'Settings could not be saved.'));
    } finally {
      setSaving(false);
    }
  }

  return <section className="settings-page">
    <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> SETTINGS</div>
    <div className="welcome-row"><div><h1>Workspace settings</h1><p className="page-subtitle">Your saved preferences and server-enforced safety controls.</p></div></div>
    {error && <div className="form-alert page-alert" role="alert">{error}<button type="button" className="text-button" onClick={() => void load()}>Retry</button></div>}
    {loading && !data ? <div className="panel-loading" role="status"><span className="loading-dot" /> Loading settings from your account…</div> : data && <>
      <article className="settings-card">
        <div className="panel-title-row"><div className="settings-title"><span className="metric-icon cyan"><SlidersHorizontal size={17} /></span><div><h2>Personal preferences</h2><p>Saved to this account and applied to your workspace.</p></div></div></div>
        <div className="settings-form-grid">
          <label>Theme<select value={theme} onChange={(event) => setTheme(event.target.value as 'dark' | 'light')}><option value="dark">Midnight dark</option><option value="light">Light</option></select><small>Changes the saved workspace color theme.</small></label>
          <label>Default report format<select value={format} onChange={(event) => setFormat(event.target.value as 'pdf' | 'json')}><option value="pdf">PDF</option><option value="json">JSON</option></select><small>Reports remain downloadable as either format.</small></label>
          <label>Report retention<select value={retention} onChange={(event) => setRetention(Number(event.target.value) as typeof retention)}><option value={0}>Keep reports until manually removed</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={180}>180 days</option><option value={365}>365 days</option></select><small>{data.reports.cleanup_behavior}</small></label>
        </div>
        <div className="settings-actions"><button className="button button-primary" type="button" onClick={() => void save()} disabled={saving || loading}><Save size={15} />{saving ? 'Saving…' : 'Save preferences'}</button>{saved && <span className="save-success" role="status"><Check size={15} /> Preferences saved to your account.</span>}</div>
      </article>

      <div className="settings-grid">
        <article className="settings-card"><div className="panel-title-row"><div className="settings-title"><span className="metric-icon violet"><ShieldCheck size={17} /></span><div><h2>Account</h2><p>Server-verified identity</p></div></div></div><dl className="settings-definition"><div><dt>Email</dt><dd>{data.user.email}</dd></div><div><dt>Account role</dt><dd>{data.user.role}</dd></div><div><dt>Created</dt><dd>{new Date(data.user.created_at).toLocaleDateString()}</dd></div><div><dt>Session lifetime</dt><dd>{data.security.session_ttl_hours} hours</dd></div><div><dt>Session cookie</dt><dd>{data.security.cookie_secure ? 'Secure' : 'Local development only'} · SameSite={data.security.cookie_samesite}</dd></div><div><dt>HSTS</dt><dd>{data.security.hsts_enabled ? 'Enabled by server configuration' : 'Not enabled in this environment'}</dd></div></dl></article>
        <article className="settings-card"><div className="panel-title-row"><div className="settings-title"><span className="metric-icon amber"><SlidersHorizontal size={17} /></span><div><h2>Scanner safety limits</h2><p>Read-only server-enforced bounds</p></div></div></div><dl className="settings-definition"><div><dt>Allowed ports</dt><dd>{data.scan_limits.allowed_ports.join(', ')}</dd></div><div><dt>Requests per scan</dt><dd>At most {data.scan_limits.max_requests_per_scan}</dd></div><div><dt>Redirects followed</dt><dd>At most {data.scan_limits.max_redirects_per_request}</dd></div><div><dt>Request timeout</dt><dd>{data.scan_limits.request_timeout_seconds} seconds</dd></div><div><dt>Maximum response body</dt><dd>{(data.scan_limits.max_response_bytes / 1024).toLocaleString()} KB</dd></div><div><dt>Concurrent scan jobs</dt><dd>{data.scan_limits.max_concurrent_jobs}</dd></div><div><dt>Maximum scan duration</dt><dd>{data.scan_limits.max_scan_duration_seconds} seconds</dd></div><div><dt>Scan starts per minute</dt><dd>{data.scan_limits.scan_rate_per_minute}</dd></div><div><dt>Targets per account</dt><dd>{data.scan_limits.max_targets_per_user}</dd></div></dl></article>
      </div>
      <article className="settings-card"><div className="panel-title-row"><div className="settings-title"><span className="metric-icon cyan"><SlidersHorizontal size={17} /></span><div><h2>Finding triage policy</h2><p>Conservative evidence-based defaults; labels are not CVSS scores.</p></div></div></div><p>{data.severity_policy.configuration}</p><dl className="settings-definition">{Object.entries(data.severity_policy.overrides).length ? Object.entries(data.severity_policy.overrides).map(([category, severity]) => <div key={category}><dt>{category.replace(/_/g, ' ')}</dt><dd>{severity}</dd></div>) : <div><dt>Overrides</dt><dd>None; use documented analyzer defaults.</dd></div>}</dl></article>
      <article className="settings-card integration-state"><div className="panel-title-row"><div className="settings-title"><span className="metric-icon red"><CircleAlert size={17} /></span><div><h2>Optional integrations</h2><p>Active scanning and the ZAP integration are disabled in this installation.</p></div></div></div><div className="integration-row"><div><strong>OWASP ZAP</strong><p>{data.integrations.owasp_zap.message}</p></div><span className="status-badge status-disabled">Not configured</span></div><p className="settings-note">No credentials, proxy URLs or integration secrets are returned by this endpoint or sent to the browser.</p></article>
      <div className="settings-footer" role="status">VulnSight API {data.api_version} · {data.environment} environment · Live health: {health?.status || 'unavailable'}{health ? ` · ${health.database.toUpperCase()} connected · API ${health.version}` : ''}</div>
    </>}
  </section>;
}
