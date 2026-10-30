import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ScanProgress from './ScanProgress';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('Scan progress evidence rendering', () => {
  it('renders persisted object evidence as safe readable text instead of a React child object', async () => {
    const scan = {
      id: 'scan-1', target_id: 'target-1', target_name: 'Synthetic local fixture',
      target_url: 'https://fixture.example/', name: 'Evidence scan', description: '',
      profile: 'standard', status: 'completed', stage: 'completed',
      started_at: '2026-10-22T10:00:00+00:00', completed_at: '2026-10-22T10:00:01+00:00',
      duration_seconds: 1, checks_total: 8, checks_completed: 8, progress_percent: 100,
      findings_count: 1, limitations: ['Synthetic local test fixture only.'], events: [],
    };
    const finding = {
      id: 'finding-1', title: 'Missing content security policy', category: 'security_headers',
      severity: 'high', affected_url: 'https://fixture.example/',
      description: 'The fixture returned no Content-Security-Policy header.',
      evidence: { missing_header: 'Content-Security-Policy', observed_headers: {} },
      remediation: 'Set an appropriate policy.', confidence: 'high', status: 'open',
    };
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const payload = url.endsWith('/findings') ? { items: [finding], total: 1 } : scan;
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }));
    render(<MemoryRouter initialEntries={['/scans/scan-1']}><Routes><Route path="/scans/:scanId" element={<ScanProgress />} /></Routes></MemoryRouter>);

    expect(await screen.findByText('Missing content security policy')).toBeInTheDocument();
    expect(await screen.findByText((_, element) => element?.tagName === 'P' && (element.textContent || '').includes('"Content-Security-Policy"'))).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Persisted events' })).toBeInTheDocument();
  });
});
