import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { ArrowRight, CheckCircle2, Globe2, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiRequest, userFacingError } from '../services/api';

type Target = {
  id: string | number;
  name: string;
  base_url: string;
  description?: string;
  allowed_hostnames?: string[];
  allowed_ports?: number[];
  scope_notes?: string;
  enabled: boolean;
  authorization_status?: string;
};

type ScanProfile = 'quick' | 'standard' | 'advanced';

type ScanCreated = {
  id: string | number;
  target_name?: string;
  target_url?: string;
  status?: string;
  stage?: string;
  checks_total?: number;
  checks_completed?: number;
  progress_percent?: number;
  limitations?: string[];
};

const profiles: Array<{ value: ScanProfile; label: string; summary: string; checks: string }> = [
  { value: 'quick', label: 'Quick', summary: 'A short, bounded baseline assessment.', checks: 'Passive checks with a smaller check set.' },
  { value: 'standard', label: 'Standard', summary: 'The recommended bounded passive assessment.', checks: 'Passive checks covering the standard check set.' },
  { value: 'advanced', label: 'Advanced', summary: 'The broadest available passive assessment.', checks: 'Passive checks only; no active exploitation or ZAP scan.' },
];

function targetPort(target: Target) {
  if (target.allowed_ports?.length) return target.allowed_ports;
  try {
    const parsed = new URL(target.base_url);
    return [parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80];
  } catch {
    return [];
  }
}

export default function ScanWizard() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [targetId, setTargetId] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('standard');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  async function loadTargets(signal?: AbortSignal) {
    setLoading(true);
    setLoadError(null);
    try {
      const result = await apiRequest<{ items: Target[]; total: number }>('/api/targets', { signal });
      const authorizedTargets = (result.items || []).filter((target) => target.enabled && target.authorization_status === 'authorized');
      setTargets(authorizedTargets);
      setTargetId((current) => authorizedTargets.some((target) => String(target.id) === current) ? current : String(authorizedTargets[0]?.id ?? ''));
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === 'AbortError') return;
      setLoadError(userFacingError(reason, 'Authorized targets could not be loaded.'));
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }

  useEffect(() => {
    const controller = new AbortController();
    void loadTargets(controller.signal);
    return () => controller.abort();
  }, []);

  const selectedTarget = useMemo(
    () => targets.find((target) => String(target.id) === targetId) || null,
    [targetId, targets],
  );
  const ports = selectedTarget ? targetPort(selectedTarget) : [];

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitError(null);
    if (!selectedTarget) {
      setSubmitError('Choose an enabled, authorized target before starting a scan.');
      return;
    }
    if (!authorizationConfirmed) {
      setSubmitError('Confirm that you have explicit authorization for the displayed scope before starting the scan.');
      return;
    }
    setSubmitting(true);
    try {
      const body: {
        target_id: string | number;
        profile: ScanProfile;
        authorization_confirmed: true;
        name?: string;
        description?: string;
      } = {
        target_id: selectedTarget.id,
        profile,
        authorization_confirmed: true,
      };
      const trimmedName = name.trim();
      const trimmedDescription = description.trim();
      if (trimmedName) body.name = trimmedName;
      if (trimmedDescription) body.description = trimmedDescription;
      const created = await apiRequest<ScanCreated>('/api/scans', { method: 'POST', body: JSON.stringify(body) });
      navigate(`/scans/${encodeURIComponent(String(created.id))}`);
    } catch (reason) {
      setSubmitError(userFacingError(reason, 'The scan could not be started.'));
    } finally {
      setSubmitting(false);
    }
  }

  return <section className="scan-wizard">
    <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> NEW SCAN</div>
    <div className="welcome-row">
      <div><h1>Configure a bounded scan</h1><p className="page-subtitle">Select a real authorized target and choose a passive assessment profile.</p></div>
    </div>
    <div className="scope-banner"><ShieldCheck size={17} /><div><strong>Passive, authorized assessments only</strong><p>Quick and Standard perform bounded passive checks. Advanced remains passive. OWASP ZAP is not configured, and no active scan is sent.</p></div></div>
    {loadError && <div className="form-alert page-alert" role="alert">{loadError}<button type="button" className="text-button" onClick={() => void loadTargets()}>Retry</button></div>}
    {loading ? <div className="target-state" role="status"><span className="loading-dot" /> Loading authorized targets…</div> : targets.length === 0 ? <div className="target-empty"><Globe2 size={25} /><h2>No enabled authorized targets</h2><p>Add and authorize a target before starting a scan. Disabled or otherwise unauthorized targets cannot be selected.</p></div> : <form className="scan-wizard-form" onSubmit={submit}>
      <section className="scan-wizard-section" aria-labelledby="scan-target-heading">
        <div className="section-heading"><span className="panel-icon cyan"><Globe2 size={16} /></span><div><h2 id="scan-target-heading">1. Select target</h2><p>Only enabled targets with current authorization are available.</p></div></div>
        <label htmlFor="scan-target">Authorized target<select id="scan-target" value={targetId} onChange={(event) => { setTargetId(event.target.value); setAuthorizationConfirmed(false); setSubmitError(null); }} required><option value="" disabled>Choose a target</option>{targets.map((target) => <option value={String(target.id)} key={String(target.id)}>{target.name} — {target.base_url}</option>)}</select></label>
        {selectedTarget && <div className="scope-preview" aria-label="Selected target scope"><div className="scope-preview-url"><span className="status-dot" /><div><strong>Exact URL</strong><a href={selectedTarget.base_url} target="_blank" rel="noopener noreferrer">{selectedTarget.base_url}</a></div></div><dl className="target-meta"><div><dt>Allowed hostnames</dt><dd>{selectedTarget.allowed_hostnames?.length ? selectedTarget.allowed_hostnames.join(', ') : 'None returned by API'}</dd></div><div><dt>Allowed ports</dt><dd>{ports.length ? ports.join(', ') : 'Not returned by API'}</dd></div><div><dt>Scope notes</dt><dd>{selectedTarget.scope_notes || 'No additional notes.'}</dd></div></dl></div>}
      </section>
      <section className="scan-wizard-section" aria-labelledby="scan-profile-heading">
        <div className="section-heading"><span className="panel-icon violet"><CheckCircle2 size={16} /></span><div><h2 id="scan-profile-heading">2. Choose profile</h2><p>All profiles remain non-destructive and passive.</p></div></div>
        <div className="scan-profile-options" role="radiogroup" aria-label="Scan profile">{profiles.map((item) => <label className={`scan-profile ${profile === item.value ? 'selected' : ''}`} key={item.value}><input type="radio" name="profile" value={item.value} checked={profile === item.value} onChange={() => setProfile(item.value)} /><span><strong>{item.label}</strong><small>{item.summary}</small><em>{item.checks}</em></span></label>)}</div>
      </section>
      <section className="scan-wizard-section" aria-labelledby="scan-details-heading">
        <div className="section-heading"><span className="panel-icon cyan"><ShieldCheck size={16} /></span><div><h2 id="scan-details-heading">3. Add details and confirm</h2><p>Optional labels help identify this assessment later.</p></div></div>
        <div className="form-grid"><label htmlFor="scan-name">Scan name <span className="label-optional">(optional)</span><input id="scan-name" value={name} maxLength={120} onChange={(event) => setName(event.target.value)} placeholder="Q4 public web baseline" /></label><label htmlFor="scan-description">Description <span className="label-optional">(optional)</span><textarea id="scan-description" rows={2} maxLength={4000} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Context for this authorized assessment" /></label></div>
        {selectedTarget && <label className="authorization-check"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} /><span><strong>I confirm I have explicit authorization for this scan</strong><small>I will keep this assessment within the exact URL, allowed hostnames, ports, and scope notes shown above.</small></span></label>}
        {submitError && <div className="form-alert" role="alert">{submitError}</div>}
        <div className="wizard-actions"><button className="button button-primary" type="submit" disabled={submitting || !selectedTarget || !authorizationConfirmed}>{submitting ? <><span className="loading-dot" /> Starting scan…</> : <>Start passive scan <ArrowRight size={15} /></>}</button></div>
      </section>
    </form>}
  </section>;
}
