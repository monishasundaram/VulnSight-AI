import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Reports from './Reports';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const summary = 'The standard assessment recorded 1 evidence-backed finding across 8 of 8 checks. Results are limited to the checks listed and do not establish complete security.';
const preview = {
  report_title: 'VulnSight AI Security Assessment Report',
  executive_summary: summary,
  finding_count: 1,
  severity_counts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
  scan: { id: 'scan-1', name: 'Synthetic report fixture', profile: 'standard', status: 'completed', started_at: '2026-10-22T10:00:00+00:00' },
  authorized_scope: { target_name: 'Synthetic authorized target', base_url: 'https://fixture.example/' },
  limitations: ['Synthetic test only.'],
  findings: [],
};

function renderReports(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter initialEntries={['/reports']}><Routes><Route path="/reports" element={<Reports />} /></Routes></MemoryRouter>);
}

describe('Report preview summary copy', () => {
  it('copies the persisted report executive summary and confirms success', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      let payload: unknown;
      if (url === '/api/reports') payload = { items: [], total: 0 };
      else if (url.startsWith('/api/reports/eligible-scans?')) payload = { items: [{ id: 'scan-1', name: 'Synthetic report fixture', target_name: 'Synthetic authorized target', status: 'completed', profile: 'standard', started_at: '2026-10-22T10:00:00+00:00', findings_count: 1 }], total: 1, page: 1, page_size: 20 };
      else if (url === '/api/settings') payload = { preferences: { default_report_format: 'pdf' } };
      else if (url === '/api/reports/scan-1') payload = preview;
      else throw new Error(`Unexpected test API path: ${url}`);
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    renderReports(fetchMock);

    fireEvent.click(await screen.findByRole('button', { name: 'Preview' }));
    expect(await screen.findByText(summary)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy executive summary' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(summary));
    expect(await screen.findByText('Executive summary copied.')).toBeInTheDocument();

    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
    else Reflect.deleteProperty(navigator, 'clipboard');
  });
});
