import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Overview from './Overview';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const emptySummary = {
  generated_at: '2026-10-22T00:00:00+00:00',
  total_scans: 0,
  targets_assessed: 0,
  open_findings: 0,
  critical_high_findings: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  comparisons: { total_scans: null, open_findings: null },
  recent_scans: [],
  recent_findings: [],
};

function fixtureScans(count: number) {
  return Array.from({ length: count }, (_, index) => ({
    id: `scan-${index + 1}`,
    name: `Fixture scan ${index + 1}`,
    target_name: `Authorized target ${index + 1}`,
    status: 'completed',
    profile: 'standard',
    started_at: '2026-10-22T10:00:00+00:00',
    duration_seconds: 1.25,
    findings_count: index,
  }));
}

function mockDashboard(scanCount = 0) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const payload = url === '/api/health'
      ? { status: 'ok', database: 'sqlite', version: '1.0.0' }
      : url === '/api/dashboard/summary'
        ? { ...emptySummary, total_scans: scanCount, targets_assessed: scanCount ? 1 : 0, recent_scans: fixtureScans(scanCount) }
        : url.startsWith('/api/scans?')
          ? { items: fixtureScans(scanCount).slice(0, 5), total: scanCount, page: 1, page_size: 5 }
          : { days: 14, items: Array.from({ length: 14 }, (_, index) => ({ date: `2026-10-${String(index + 9).padStart(2, '0')}`, scans: 0, findings: 0 })) };
    return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('Overview API connection', () => {
  it('renders backend-derived empty states and never substitutes sample counts', async () => {
    mockDashboard();
    render(<MemoryRouter><Overview /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText('Total scans')).toBeInTheDocument());
    expect(screen.getByText(/NO SCANS RECORDED/i)).toBeInTheDocument();
    expect(screen.getByText(/no sample findings or fabricated metrics/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /configure a new scan/i })).toHaveAttribute('href', '/scan/new');
    expect(screen.getByText(/SQLITE persistence ready/i)).toBeInTheDocument();
    expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(4);
    expect(screen.getByText(/no scan activity in this time window/i)).toBeInTheDocument();
    expect(screen.getByText(/no active findings are recorded/i)).toBeInTheDocument();
    expect(screen.getByText('No scans are recorded yet.')).toBeInTheDocument();
  });

  it('shows persisted table results and sends search/sort/page requests to the scan API', async () => {
    const fetchMock = mockDashboard(3);
    render(<MemoryRouter><Overview /></MemoryRouter>);
    await waitFor(() => expect(screen.getByText('Fixture scan 1')).toBeInTheDocument());
    expect(screen.getByText('Monitor, assess, and improve your web application security.')).toBeInTheDocument();
    expect(screen.getByText('Showing 1–3 of 3')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Search scan name, target, URL or ID'), { target: { value: 'fixture' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(fetchMock.mock.calls.some((call) => String(call[0]).includes('query=fixture'))).toBe(true));

    fireEvent.change(screen.getByLabelText('Sort recent scans'), { target: { value: 'findings_count:desc' } });
    await waitFor(() => expect(fetchMock.mock.calls.some((call) => String(call[0]).includes('sort=findings_count'))).toBe(true));
  });
});
