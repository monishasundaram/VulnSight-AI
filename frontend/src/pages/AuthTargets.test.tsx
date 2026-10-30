import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthProvider } from '../services/auth';
import AuthPage from './AuthPage';
import Targets from './Targets';
import ScanWizard from './ScanWizard';
import { ProtectedRoute, PublicOnlyRoute } from '../components/RouteGuards';

function renderAuth(path = '/login') { return render(<MemoryRouter initialEntries={[path]}><AuthProvider><AuthPage mode={path === '/register' ? 'register' : 'login'} /></AuthProvider></MemoryRouter>); }
function renderTargets() { return render(<MemoryRouter><AuthProvider><Targets /></AuthProvider></MemoryRouter>); }

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('authenticated API boundary', () => {
  it('shows the server-enforced 12-character minimum on account creation', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 401 })));
    renderAuth('/register');
    await waitFor(() => expect(screen.getByRole('button', { name: /create account/i })).toBeEnabled());

    expect(screen.getByLabelText(/password/i)).toHaveAttribute('minlength', '12');
    expect(screen.getByText('Use at least 12 characters.')).toBeInTheDocument();
  });

  it('shows session loading then an API login error without fake access', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response('', { status: 401 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'Invalid email or password.' }), { status: 401 }));
    vi.stubGlobal('fetch', fetchMock);
    renderAuth();
    await waitFor(() => expect(screen.getByRole('button', { name: /sign in/i })).toBeEnabled());
    fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'user@example.com' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong-password' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Invalid email or password.'));
    expect(screen.queryByText(/security overview/i)).not.toBeInTheDocument();
  });

  it('bootstraps an authenticated session from /me', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ user: { id: 'u1', email: 'owner@example.com', role: 'owner' }, csrfToken: 'csrf-1' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/login']}><AuthProvider><Routes><Route element={<PublicOnlyRoute />}><Route path="/login" element={<AuthPage mode="login" />} /></Route><Route path="/" element={<h1>Authenticated workspace</h1>} /></Routes></AuthProvider></MemoryRouter>);
    await waitFor(() => expect(screen.getByRole('heading', { name: /authenticated workspace/i })).toBeInTheDocument());
  });

  it('redirects a stale signed-in tab to sign-in when a protected request returns 401', async () => {
    const fetchMock = vi.fn().mockImplementation((input: RequestInfo | URL) => {
      if (String(input).includes('/api/auth/me')) {
        return Promise.resolve(new Response(JSON.stringify({ user: { id: 'u1', email: 'owner@example.com', role: 'user' }, csrfToken: 'csrf-1' }), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ detail: 'Authentication required' }), { status: 401 }));
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scan/new']}><AuthProvider><Routes>
      <Route element={<ProtectedRoute />}><Route path="/scan/new" element={<ScanWizard />} /></Route>
      <Route path="/login" element={<AuthPage mode="login" />} />
    </Routes></AuthProvider></MemoryRouter>);

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Welcome back' })).toBeInTheDocument());
    expect(screen.getByRole('alert')).toHaveTextContent('Your session expired or is no longer valid. Please sign in again.');
  });
});

describe('targets API boundary', () => {
  const session = { user: { id: 'u1', email: 'owner@example.com', role: 'owner' }, csrfToken: 'csrf-1' };
  it('renders the database empty state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((input: RequestInfo | URL) => Promise.resolve(new Response(String(input).includes('/auth/me') ? JSON.stringify(session) : JSON.stringify({ items: [], total: 0 }), { status: 200 }))));
    renderTargets();
    await waitFor(() => expect(screen.getByRole('heading', { name: /no authorized targets/i })).toBeInTheDocument());
    expect(screen.queryByText(/sample target/i)).not.toBeInTheDocument();
  });

  it('renders a live target and keeps creation disabled until authorization is explicit', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation((input: RequestInfo | URL) => Promise.resolve(new Response(String(input).includes('/auth/me') ? JSON.stringify(session) : JSON.stringify({ items: [{ id: 't1', name: 'Example', base_url: 'https://example.com', allowed_hostnames: ['example.com'], scope_notes: 'Public only', enabled: true }], total: 1 }), { status: 200 }))));
    renderTargets();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Example' })).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: /add target/i }));
    expect(screen.getByRole('button', { name: /create target/i })).toBeDisabled();
    fireEvent.click(screen.getByRole('checkbox', { name: /explicit authorization/i }));
    expect(screen.getByRole('button', { name: /create target/i })).toBeEnabled();
  });
});
