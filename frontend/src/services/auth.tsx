import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { apiRequest, SESSION_EXPIRED_EVENT, setCsrfToken, userFacingError } from './api';

export type User = { id: string | number; email: string; role: string };
type AuthResponse = { user: User; csrfToken: string };
type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

type AuthContextValue = {
  status: AuthStatus;
  user: User | null;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  clearError: () => void;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [user, setUser] = useState<User | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const handleSessionExpired = () => {
      setCsrfToken(null);
      setUser(null);
      setStatus('unauthenticated');
      setError('Your session expired or is no longer valid. Please sign in again.');
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
    apiRequest<AuthResponse>('/api/auth/me')
      .then((response) => {
        if (!active) return;
        setCsrfToken(response.csrfToken);
        setUser(response.user);
        setStatus('authenticated');
      })
      .catch((reason: unknown) => {
        if (!active) return;
        setCsrfToken(null);
        setUser(null);
        setStatus('unauthenticated');
        if (reason && typeof reason === 'object' && 'status' in reason && (reason as { status?: number }).status !== 401) {
          setError(userFacingError(reason, 'Unable to check your session.'));
        }
      });
    return () => {
      active = false;
      window.removeEventListener(SESSION_EXPIRED_EVENT, handleSessionExpired);
    };
  }, []);

  const authenticate = useCallback(async (action: 'login' | 'register', email: string, password: string) => {
    setError(null);
    const response = await apiRequest<AuthResponse>(`/api/auth/${action}`, {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setCsrfToken(response.csrfToken);
    setUser(response.user);
    setStatus('authenticated');
  }, []);

  const login = useCallback((email: string, password: string) => authenticate('login', email, password), [authenticate]);
  const register = useCallback((email: string, password: string) => authenticate('register', email, password), [authenticate]);

  const logout = useCallback(async () => {
    setError(null);
    try {
      await apiRequest<void>('/api/auth/logout', { method: 'POST' });
    } catch (reason) {
      setError(userFacingError(reason, 'Unable to sign out cleanly.'));
    } finally {
      setCsrfToken(null);
      setUser(null);
      setStatus('unauthenticated');
    }
  }, []);

  const value = useMemo(() => ({ status, user, error, login, register, logout, clearError: () => setError(null) }), [status, user, error, login, register, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
