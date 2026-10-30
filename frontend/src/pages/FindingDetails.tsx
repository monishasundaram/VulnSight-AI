import { useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import { apiRequest, userFacingError } from '../services/api';

type FindingHistory = {
  id: string | number;
  previous_status?: string;
  new_status?: string;
  justification?: string;
  changed_at?: string;
};
type Finding = {
  id: string | number;
  scan_id?: string | number;
  title?: string;
  category?: string;
  severity?: string;
  affected_url?: string;
  description?: string;
  evidence?: unknown;
  impact?: string;
  remediation?: string;
  references?: unknown;
  confidence?: string;
  verification_status?: string;
  status?: string;
  detected_at?: string | null;
  scan?: { id?: string | number; name?: string; profile?: string; status?: string; started_at?: string } | null;
  target?: { id?: string | number; name?: string; base_url?: string } | null;
  status_history?: FindingHistory[];
};
const statusOptions = ['open', 'in_progress', 'resolved', 'accepted_risk'] as const;

function label(value?: string) { return value ? value.replace(/_/g, ' ') : 'Unknown'; }
function displayDate(value?: string | null) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
function evidenceText(value: unknown) {
  if (value === undefined || value === null) return 'No evidence recorded.';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}
function expectedAndObserved(category: string | undefined, value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { expected: 'The check expectation is described by the finding.', observed: evidenceText(value) };
  }
  const evidence = value as Record<string, unknown>;
  let expected = typeof evidence.expected_setting === 'string'
    ? evidence.expected_setting : 'The check expectation is described by the finding; no separate expected value was recorded.';
  let observed: string;
  if (typeof evidence.observed_name === 'string') {
    observed = evidence.present_policy === false
      ? `${evidence.observed_name}: not present`
      : `${evidence.observed_name}: ${typeof evidence.observed_value === 'string' ? evidence.observed_value : evidence.present_policy === true ? 'present; value not recorded' : 'not reported'}`;
  } else if (Array.isArray(evidence.observed_attributes)) {
    const attributes = evidence.observed_attributes.filter((item): item is string => typeof item === 'string');
    observed = `${typeof evidence.cookie_name === 'string' ? `Cookie ${evidence.cookie_name}; ` : ''}attributes observed: ${attributes.length ? attributes.join(', ') : 'none'}`;
  } else if (category === 'tls') {
    expected = 'A reachable HTTPS endpoint with a currently valid, trusted certificate matching the authorized hostname; legacy TLS versions should not be negotiated.';
    observed = `TLS assessment: ${evidenceText(evidence)}`;
  } else if (category === 'input_validation') {
    expected = 'The benign, non-executable query marker should not be reflected into a potentially unsafe output context; reflection alone does not prove execution.';
    observed = `Safe GET observation: ${evidenceText(evidence)}`;
  } else if (category === 'transport') {
    expected = 'HTTP should upgrade to HTTPS within the authorized hostname scope, without a downgrade.';
    observed = `Redirect decision: ${evidenceText(evidence)}`;
  } else if (category === 'response_configuration') {
    expected = 'Avoid disclosing unnecessary server implementation or version details.';
    observed = `Response headers observed: ${evidenceText(evidence)}`;
  } else {
    observed = evidenceText(evidence);
  }
  return { expected, observed };
}
function isExternalUrl(value: unknown): value is string {
  return typeof value === 'string' && /^https?:\/\//i.test(value);
}

export default function FindingDetails() {
  const { findingId } = useParams<{ findingId: string }>();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nextStatus, setNextStatus] = useState('');
  const [justification, setJustification] = useState('');
  const [transitionError, setTransitionError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function loadFinding() {
    if (!findingId) {
      setError('This finding link is missing an ID.');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const response = await apiRequest<Finding>(`/api/findings/${encodeURIComponent(findingId)}`);
      setFinding(response);
      setNextStatus(response.status || '');
    } catch (reason) {
      setFinding(null);
      setError(userFacingError(reason, 'Finding details could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { void loadFinding(); }, [findingId]);

  const currentStatus = finding?.status || '';
  const requiresJustification = nextStatus === 'accepted_risk' || nextStatus === 'open' && (currentStatus === 'resolved' || currentStatus === 'accepted_risk');

  async function changeStatus(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!finding || !findingId || !nextStatus) return;
    setTransitionError(null);
    const cleaned = justification.trim();
    if (requiresJustification && cleaned.length < 10) {
      setTransitionError('Provide at least 10 characters of justification for accepting risk or reopening a finding.');
      return;
    }
    setSaving(true);
    try {
      const response = await apiRequest<Finding>(`/api/findings/${encodeURIComponent(findingId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus, justification: cleaned }),
      });
      setFinding(response);
      setNextStatus(response.status || '');
      setJustification('');
    } catch (reason) {
      // userFacingError preserves the API's detail/message when the server rejects the transition.
      setTransitionError(userFacingError(reason, 'The finding status could not be updated.'));
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <section className="finding-detail"><div className="data-state" role="status"><span className="loading-dot" /> Loading finding details…</div></section>;
  if (error || !finding) return <section className="finding-detail"><div className="form-alert page-alert" role="alert"><span>{error || 'Finding details are unavailable.'}</span><button className="text-button" type="button" onClick={() => void loadFinding()}>Retry</button></div></section>;

  const references = Array.isArray(finding.references) ? finding.references : [];
  const history = Array.isArray(finding.status_history) ? finding.status_history : [];
  const comparison = expectedAndObserved(finding.category, finding.evidence);
  const remediationSteps = (finding.remediation || '').split(/;\s*/).map((step) => step.trim()).filter(Boolean);

  return (
    <section className="finding-detail">
      <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> FINDING DETAILS</div>
      <div className="welcome-row">
        <div><p className="detail-back"><Link to="/findings">← Back to vulnerabilities</Link></p><h1>{finding.title || `Finding ${finding.id}`}</h1><p className="page-subtitle">{finding.category || 'Uncategorized'} · detected {displayDate(finding.detected_at)}</p></div>
        <div className="detail-badges"><span className={`severity-badge severity-${finding.severity || 'unknown'}`}>{label(finding.severity)}</span><span className={`status-badge status-${finding.status || 'unknown'}`}>{label(finding.status)}</span></div>
      </div>

      <div className="finding-context" aria-label="Finding context">
        <div><dt>Target</dt><dd>{finding.target?.name || 'Unavailable target'}{finding.target?.base_url && <small>{finding.target.base_url}</small>}</dd></div>
        <div><dt>Scan</dt><dd>{finding.scan?.name || 'Unavailable scan'}{finding.scan?.id && <Link to={`/scans/${encodeURIComponent(String(finding.scan.id))}`}>View scan</Link>}</dd></div>
        <div><dt>Profile / scan status</dt><dd>{label(finding.scan?.profile)} / {label(finding.scan?.status)}</dd></div>
        <div><dt>Confidence</dt><dd>{label(finding.confidence)}</dd></div>
        <div><dt>Verification</dt><dd>{label(finding.verification_status)}</dd></div>
      </div>

      <div className="finding-detail-grid">
        <div className="finding-detail-main">
          <section className="detail-panel"><h2>Description</h2><p>{finding.description || 'No description recorded.'}</p><p className="affected-url"><strong>Affected URL</strong> <code>{finding.affected_url || 'Unavailable'}</code></p></section>
          <section className="detail-panel"><h2>Expected vs observed</h2><dl className="finding-context"><div><dt>Expected</dt><dd>{comparison.expected}</dd></div><div><dt>Observed</dt><dd>{comparison.observed}</dd></div></dl><details><summary>Raw redacted evidence</summary><pre className="evidence-block">{evidenceText(finding.evidence)}</pre></details></section>
          <section className="detail-panel"><h2>Impact</h2><p>{finding.impact || 'No impact description recorded.'}</p></section>
          <section className="detail-panel"><h2>Remediation</h2>{remediationSteps.length ? <ol>{remediationSteps.map((step, index) => <li key={`${index}-${step}`}>{step}</li>)}</ol> : <p>No remediation guidance recorded.</p>}</section>
          <section className="detail-panel"><h2>References</h2>{references.length ? <ul className="reference-list">{references.map((reference, index) => <li key={`${String(reference)}-${index}`}>{isExternalUrl(reference) ? <a href={reference} target="_blank" rel="noopener noreferrer">{reference}</a> : String(reference)}</li>)}</ul> : <p>No references recorded.</p>}</section>
        </div>
        <aside className="finding-detail-side">
          <section className="detail-panel"><h2>Update status</h2><form className="status-form" onSubmit={changeStatus}>
            <label htmlFor="finding-status">New status<select id="finding-status" value={nextStatus} onChange={(event) => { setNextStatus(event.target.value); setTransitionError(null); }}>{statusOptions.map((value) => <option value={value} key={value}>{label(value)}</option>)}</select></label>
            <label htmlFor="status-justification">Justification{requiresJustification && <small>Required: at least 10 characters.</small>}<textarea id="status-justification" rows={5} value={justification} onChange={(event) => { setJustification(event.target.value); if (transitionError) setTransitionError(null); }} placeholder={requiresJustification ? 'Explain the risk decision or why this finding is being reopened.' : 'Optional transition context'} aria-describedby="justification-help" /></label>
            <small id="justification-help" className={requiresJustification && justification.trim().length < 10 ? 'field-error' : ''}>{requiresJustification ? `${justification.trim().length}/10 characters minimum` : 'The server records this note in the status history.'}</small>
            {transitionError && <div className="form-alert" role="alert">{transitionError}</div>}
            <button className="button button-primary" type="submit" disabled={saving || nextStatus === currentStatus}>{saving ? <><span className="loading-dot" /> Saving…</> : 'Save status'}</button>
          </form></section>
          <section className="detail-panel"><h2>Status history</h2>{history.length ? <ol className="status-history">{history.map((entry) => <li key={String(entry.id)}><div><strong>{label(entry.previous_status)} → {label(entry.new_status)}</strong><time dateTime={entry.changed_at}>{displayDate(entry.changed_at)}</time></div>{entry.justification && <p>{entry.justification}</p>}</li>)}</ol> : <p>No status changes recorded.</p>}</section>
        </aside>
      </div>
    </section>
  );
}
