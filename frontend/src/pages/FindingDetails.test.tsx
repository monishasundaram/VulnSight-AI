import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import FindingDetails from './FindingDetails';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

function renderFinding(evidence: unknown, category = 'security_headers') {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
    id: 'finding-1',
    scan_id: 'scan-1',
    title: 'Evidence-backed finding',
    category,
    severity: 'low',
    affected_url: 'https://example.invalid/',
    description: 'Synthetic unit-test finding.',
    evidence,
    impact: 'Context matters.',
    remediation: 'Review the setting.',
    references: [],
    confidence: 'low',
    verification_status: 'observed',
    status: 'open',
    detected_at: '2026-01-01T00:00:00Z',
    scan: { id: 'scan-1', name: 'Synthetic test', profile: 'quick', status: 'completed' },
    target: { id: 'target-1', name: 'Synthetic target', base_url: 'https://example.invalid/' },
    status_history: [],
  }), { status: 200, headers: { 'Content-Type': 'application/json' } })));
  render(<MemoryRouter initialEntries={['/findings/finding-1']}><Routes><Route path="/findings/:findingId" element={<FindingDetails />} /></Routes></MemoryRouter>);
}

describe('finding details evidence comparison', () => {
  it('shows the expected header setting and records an absent header as the observation', async () => {
    renderFinding({
      expected_setting: 'A deliberate Content-Security-Policy',
      observed_name: 'Content-Security-Policy',
      present_policy: false,
    });

    expect(await screen.findByRole('heading', { name: 'Expected vs observed' })).toBeInTheDocument();
    expect(screen.getByText('A deliberate Content-Security-Policy')).toBeInTheDocument();
    expect(screen.getByText('Content-Security-Policy: not present')).toBeInTheDocument();
  });

  it('shows cookie names and attributes without exposing cookie values', async () => {
    renderFinding({ cookie_name: 'session', expected_setting: 'HttpOnly', observed_attributes: ['Secure', 'SameSite=lax'] }, 'cookies');

    expect(await screen.findByText('HttpOnly')).toBeInTheDocument();
    expect(screen.getByText('Cookie session; attributes observed: Secure, SameSite=lax')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('secret-cookie-value');
  });
});
