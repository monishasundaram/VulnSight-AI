import { useEffect, useState, type FormEvent } from 'react';
import { Edit3, Globe2, Plus, Save, ShieldCheck, ToggleLeft, ToggleRight, Trash2, X } from 'lucide-react';
import { apiRequest, userFacingError } from '../services/api';
import { Link } from 'react-router-dom';

type Target = {
  id: string | number;
  name: string;
  base_url: string;
  description?: string;
  owner_reference?: string;
  allowed_hostnames?: string[];
  scope_notes?: string;
  enabled: boolean;
  authorization_status?: string;
  last_scan_at?: string | null;
};
type TargetDraft = {
  name: string;
  base_url: string;
  description: string;
  owner_reference: string;
  allowed_hostnames: string;
  scope_notes: string;
};
const emptyDraft: TargetDraft = { name: '', base_url: '', description: '', owner_reference: '', allowed_hostnames: '', scope_notes: '' };
function targetToDraft(target: Target): TargetDraft {
  return {
    name: target.name,
    base_url: target.base_url,
    description: target.description || '',
    owner_reference: target.owner_reference || '',
    allowed_hostnames: (target.allowed_hostnames || []).join('\n'),
    scope_notes: target.scope_notes || '',
  };
}
function hostnames(value: string) {
  return value.split(/[\n,]+/).map((host) => host.trim().toLowerCase()).filter(Boolean);
}

function displayLastScan(value?: string | null) {
  if (!value) return 'Never';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function Targets() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Target | null>(null);
  const [draft, setDraft] = useState<TargetDraft>(emptyDraft);
  const [authorized, setAuthorized] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  async function loadTargets() {
    setLoading(true);
    setError(null);
    try {
      const result = await apiRequest<{ items: Target[]; total: number }>('/api/targets');
      setTargets(result.items || []);
    } catch (reason) {
      setError(userFacingError(reason, 'Targets could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => { void loadTargets(); }, []);

  function openCreate() {
    setEditing(null);
    setDraft(emptyDraft);
    setAuthorized(false);
    setSaveError(null);
    setShowForm(true);
  }
  function openEdit(target: Target) {
    setEditing(target);
    setDraft(targetToDraft(target));
    setAuthorized(false);
    setSaveError(null);
    setShowForm(true);
  }
  function closeForm() {
    if (!saving) {
      setShowForm(false);
      setEditing(null);
    }
  }
  function update(field: keyof TargetDraft, value: string) {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!editing && !authorized) return;
    setSaving(true);
    setSaveError(null);
    const body = {
      name: draft.name.trim(),
      base_url: draft.base_url.trim(),
      description: draft.description.trim(),
      owner_reference: draft.owner_reference.trim(),
      allowed_hostnames: hostnames(draft.allowed_hostnames),
      scope_notes: draft.scope_notes.trim(),
      authorization_confirmed: authorized,
      ...(editing ? { enabled: editing.enabled } : {}),
    };
    try {
      if (editing) {
        await apiRequest<Target>(`/api/targets/${encodeURIComponent(String(editing.id))}`, { method: 'PATCH', body: JSON.stringify(body) });
      } else {
        await apiRequest<Target>('/api/targets', { method: 'POST', body: JSON.stringify(body) });
      }
      closeForm();
      await loadTargets();
    } catch (reason) {
      setSaveError(userFacingError(reason, 'The target could not be saved.'));
    } finally {
      setSaving(false);
    }
  }

  async function toggle(target: Target) {
    setError(null);
    if (!target.enabled && !window.confirm('Re-enable this target only if you still have explicit authorization for its listed hosts and standard HTTP(S) port. Continue?')) return;
    try {
      await apiRequest<Target>(`/api/targets/${encodeURIComponent(String(target.id))}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !target.enabled, ...(!target.enabled ? { authorization_confirmed: true } : {}) }),
      });
      await loadTargets();
    } catch (reason) {
      setError(userFacingError(reason, 'The target status could not be updated.'));
    }
  }

  async function removeTarget(target: Target) {
    const confirmed = window.confirm(`Delete “${target.name}”? This is allowed only when the target has no scan history. Existing scan/finding/audit records are preserved; disable a target instead if it has history.`);
    if (!confirmed) return;
    setError(null);
    try {
      await apiRequest<void>(`/api/targets/${encodeURIComponent(String(target.id))}`, { method: 'DELETE' });
      await loadTargets();
    } catch (reason) {
      setError(userFacingError(reason, 'The target could not be deleted.'));
    }
  }

  return <section className="targets-page">
    <div className="page-eyebrow"><span className="eyebrow-line" /> SECURITY WORKSPACE <span className="eyebrow-divider">/</span> TARGETS</div>
    <div className="welcome-row">
      <div><h1>Authorized targets</h1><p className="page-subtitle">Manage persisted web destinations that your workspace is authorized to assess.</p></div>
      <button className="button button-primary" type="button" onClick={openCreate}><Plus size={16} /> Add target</button>
    </div>
    <div className="scope-banner"><ShieldCheck size={17} /><div><strong>Scope guardrails</strong><p>Only public HTTP(S) destinations on ports <b>80 or 443</b> are supported. Add hostnames you own or have explicit authorization to assess; private networks and other ports are not in scope.</p></div></div>
    {error && <div className="form-alert page-alert" role="alert">{error}<button type="button" className="text-button" onClick={() => void loadTargets()}>Retry</button></div>}
    {loading ? <div className="target-state" role="status"><span className="loading-dot" /> Loading authorized targets…</div>
      : targets.length === 0 ? <div className="target-empty"><Globe2 size={25} /><h2>No authorized targets yet</h2><p>Targets are loaded from your workspace database. Add one only after confirming explicit authorization.</p><button className="button button-secondary" type="button" onClick={openCreate}><Plus size={15} /> Add your first target</button></div>
        : <div className="target-grid">{targets.map((target) => <article className={`target-card ${target.enabled ? '' : 'target-disabled'}`} key={String(target.id)}>
          <div className="target-card-heading"><span className="target-icon"><Globe2 size={18} /></span><div><h2>{target.name}</h2><a href={target.base_url} target="_blank" rel="noopener noreferrer">{target.base_url}</a></div><span className={`target-status ${target.enabled ? 'enabled' : 'disabled'}`}>{target.enabled ? 'Enabled' : 'Disabled'}</span></div>
          <p className="target-description">{target.description || 'No description provided.'}</p>
          <dl className="target-meta">
            <div><dt>Authorization</dt><dd>{target.authorization_status || 'Not confirmed'}</dd></div>
            <div><dt>Owner reference</dt><dd>{target.owner_reference || 'Not provided'}</dd></div>
            <div><dt>Allowed hostnames</dt><dd>{target.allowed_hostnames?.length ? target.allowed_hostnames.join(', ') : 'Base hostname only'}</dd></div>
            <div><dt>Last scan</dt><dd>{displayLastScan(target.last_scan_at)}</dd></div>
            <div><dt>Scope notes</dt><dd>{target.scope_notes || 'No additional notes.'}</dd></div>
          </dl>
          <div className="target-actions">
            <Link className="button button-secondary" to={`/scans?target_id=${encodeURIComponent(String(target.id))}`}>View scans</Link>
            <Link className="button button-quiet" to={`/findings?target_id=${encodeURIComponent(String(target.id))}`}>Review findings</Link>
            <button className="button button-secondary" type="button" onClick={() => openEdit(target)}><Edit3 size={14} /> Edit</button>
            <button className="button button-quiet" type="button" onClick={() => void toggle(target)}>{target.enabled ? <ToggleLeft size={16} /> : <ToggleRight size={16} />} {target.enabled ? 'Disable' : 'Enable'}</button>
            <button className="button button-quiet" type="button" onClick={() => void removeTarget(target)} aria-label={`Delete ${target.name}`}><Trash2 size={15} /> Delete</button>
          </div>
        </article>)}</div>}
    {showForm && <div className="modal-backdrop" role="presentation"><section className="target-modal" role="dialog" aria-modal="true" aria-labelledby="target-form-title">
      <div className="modal-heading"><div><span className="page-eyebrow"><span className="eyebrow-line" /> {editing ? 'EDIT TARGET' : 'NEW TARGET'}</span><h2 id="target-form-title">{editing ? 'Update target details' : 'Add an authorized target'}</h2></div><button className="icon-button" type="button" aria-label="Close target form" onClick={closeForm}><X size={18} /></button></div>
      <form onSubmit={save} className="target-form">
        <label>Name<input required value={draft.name} onChange={(event) => update('name', event.target.value)} placeholder="Acme public web" /></label>
        <label>Base URL<input required type="url" value={draft.base_url} onChange={(event) => update('base_url', event.target.value)} placeholder="https://example.com" /><small>Use a public http:// or https:// URL on port 80 or 443.</small></label>
        <div className="form-grid"><label>Owner reference<input required value={draft.owner_reference} onChange={(event) => update('owner_reference', event.target.value)} placeholder="Ticket, contract, or owner ID" /></label><label>Allowed hostnames<textarea required rows={2} value={draft.allowed_hostnames} onChange={(event) => update('allowed_hostnames', event.target.value)} placeholder="app.example.com\nwww.example.com" /><small>One hostname per line; these are the only hosts in scope.</small></label></div>
        <label>Description<textarea rows={2} value={draft.description} onChange={(event) => update('description', event.target.value)} /></label>
        <label>Scope notes<textarea required rows={3} value={draft.scope_notes} onChange={(event) => update('scope_notes', event.target.value)} placeholder="Document boundaries, exclusions, and the authorization context." /></label>
        <label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span><strong>{editing ? 'Reconfirm authorization for any scope change' : 'I confirm I have explicit authorization'}</strong><small>I own or have permission to assess this target and will keep testing within the hosts and public ports documented above. The server requires this confirmation to expand/change scope or re-enable a disabled target.</small></span></label>
        {saveError && <div className="form-alert" role="alert">{saveError}</div>}
        <div className="modal-actions"><button className="button button-secondary" type="button" onClick={closeForm}>Cancel</button><button className="button button-primary" type="submit" disabled={saving || (!editing && !authorized)}>{saving ? <><span className="loading-dot" /> Saving…</> : <><Save size={15} /> {editing ? 'Save changes' : 'Create target'}</>}</button></div>
      </form>
    </section></div>}
  </section>;
}
