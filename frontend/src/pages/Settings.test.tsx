import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Settings from './Settings';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('live Settings health', () => {
  it('uses the real health API response instead of a hardcoded status', async () => {
    const settings = {
      user: { id: 'owner-1', email: 'owner@example.com', role: 'owner', created_at: '2026-10-22T10:00:00+00:00' },
      preferences: { theme: 'dark', default_report_format: 'pdf', report_retention_days: 0 },
      scan_limits: { allowed_ports: [80, 443], max_requests_per_scan: 8, max_redirects_per_request: 3, request_timeout_seconds: 8, max_response_bytes: 524288, max_concurrent_jobs: 2, max_scan_duration_seconds: 60, scan_rate_per_minute: 6, max_targets_per_user: 100 },
      security: { session_ttl_hours: 12, cookie_secure: true, cookie_samesite: 'none', hsts_enabled: true },
      reports: { retention_days: 0, cleanup_behavior: 'No cleanup configured.', max_retention_days: 365 },
      integrations: { owasp_zap: { configured: false, active_scanning_enabled: false, message: 'OWASP ZAP is not configured.' } },
      severity_policy: { overrides: {}, configuration: 'Deployment policy; defaults are evidence-based labels.' },
      api_version: '1.0.0', environment: 'local',
    };
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const payload = String(input) === '/api/health'
        ? { status: 'ok', database: 'sqlite', version: '1.0.0' }
        : settings;
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/settings']}><Routes><Route path="/settings" element={<Settings />} /></Routes></MemoryRouter>);

    expect(await screen.findByText(/Live health: ok · SQLITE connected · API 1.0.0/)).toBeInTheDocument();
    expect(screen.getByText('Finding triage policy')).toBeInTheDocument();
    expect(screen.getByText('None; use documented analyzer defaults.')).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => String(input) === '/api/health')).toBe(true);
  });
});
