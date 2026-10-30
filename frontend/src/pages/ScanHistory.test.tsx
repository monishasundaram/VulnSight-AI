import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ScanHistory from './ScanHistory';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('target-scoped scan history navigation', () => {
  it('selects the deep-linked target and requests only its persisted scans', async () => {
    const requests: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requests.push(url);
      const payload = url.startsWith('/api/targets')
        ? { items: [{ id: 'target-7', name: 'Fixture target', enabled: true }], total: 1 }
        : { items: [], total: 0, page: 1, page_size: 20 };
      return new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/scans?target_id=target-7']}><Routes><Route path="/scans" element={<ScanHistory />} /></Routes></MemoryRouter>);

    expect(await screen.findByRole('heading', { name: 'No scans match these filters' })).toBeInTheDocument();
    expect(screen.getByLabelText('Target')).toHaveValue('target-7');
    await waitFor(() => expect(requests.some((url) => url.startsWith('/api/scans?') && url.includes('target_id=target-7'))).toBe(true));
  });
});
