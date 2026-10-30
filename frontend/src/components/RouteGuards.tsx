import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../services/auth';

export function AuthLoading() {
  return <main className="auth-loading" aria-live="polite"><span className="loading-dot" /> Checking your secure session…</main>;
}

export function ProtectedRoute() {
  const { status } = useAuth();
  const location = useLocation();
  if (status === 'loading') return <AuthLoading />;
  if (status !== 'authenticated') return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}

export function PublicOnlyRoute() {
  const { status } = useAuth();
  if (status === 'loading') return <AuthLoading />;
  if (status === 'authenticated') return <Navigate to="/" replace />;
  return <Outlet />;
}
