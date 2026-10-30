import { FormEvent, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import { useAuth } from '../services/auth';
import { userFacingError } from '../services/api';

type Props = { mode: 'login' | 'register' };

export default function AuthPage({ mode }: Props) {
  const isRegister = mode === 'register';
  const { login, register, error: sessionError, clearError } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    clearError();
    setBusy(true);
    try {
      if (isRegister) await register(email.trim(), password);
      else await login(email.trim(), password);
      const destination = (location.state as { from?: string } | null)?.from || '/';
      navigate(destination, { replace: true });
    } catch (reason) {
      setFormError(userFacingError(reason, isRegister ? 'We could not create that account.' : 'We could not sign you in.'));
    } finally {
      setBusy(false);
    }
  }

  const message = formError || sessionError;
  return <main className="auth-page">
    <section className="auth-card" aria-labelledby="auth-title">
      <div className="auth-brand"><span className="brand-mark" aria-hidden="true"><ShieldCheck size={20} /></span><span><b>VulnSight</b><small>AI SECURITY WORKSPACE</small></span></div>
      <div className="page-eyebrow"><span className="eyebrow-line" /> SECURE ACCESS</div>
      <h1 id="auth-title">{isRegister ? 'Create your workspace account' : 'Welcome back'}</h1>
      <p className="auth-subtitle">{isRegister ? 'Use a real account to access authorized security workflows.' : 'Sign in to continue to your authorized security workspace.'}</p>
      {message && <div className="form-alert" role="alert">{message}</div>}
      <form onSubmit={submit} className="auth-form">
        <label htmlFor="email">Email address<input id="email" name="email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} /></label>
        <label htmlFor="password">Password<input id="password" name="password" type="password" autoComplete={isRegister ? 'new-password' : 'current-password'} minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} /><small>{isRegister ? 'Use at least 12 characters.' : 'Use the same 12-character minimum password; it is sent only over the secure API session.'}</small></label>
        <button className="button button-primary auth-submit" type="submit" disabled={busy}>{busy ? <><span className="loading-dot" /> {isRegister ? 'Creating account…' : 'Signing in…'}</> : <>{isRegister ? 'Create account' : 'Sign in'} <ArrowRight size={15} /></>}</button>
      </form>
      <p className="auth-switch">{isRegister ? 'Already have an account?' : 'Need an account?'} <Link to={isRegister ? '/login' : '/register'} onClick={() => clearError()}>{isRegister ? 'Sign in' : 'Create one'}</Link></p>
      <p className="auth-footnote">Authorized assessments only. Session credentials stay in secure cookies; no credentials are stored in URLs or browser storage.</p>
    </section>
  </main>;
}
