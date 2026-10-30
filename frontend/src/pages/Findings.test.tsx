import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Findings from './Findings';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('target-scoped findings navigation', () => {
  it('passes the deep-linked target identifier to the owner-scoped findings API', async () => {
    const requests: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      requests.push(String(input));
      return new Response(JSON.stringify({ items: [], total: 0, categories: [], scans: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    vi.stubGlobal('fetch', fetchMock);
    render(<MemoryRouter initialEntries={['/findings?target_id=target-7']}><Routes><Route path="/findings" element={<Findings />} /></Routes></MemoryRouter>);

    expect(await screen.findByRole('status')).toHaveTextContent('Showing findings for target target-7');
    expect(await screen.findByRole('heading', { name: 'No vulnerabilities match these filters' })).toBeInTheDocument();
    await waitFor(() => expect(requests.some((url) => url.includes('/api/findings?') && url.includes('target_id=target-7'))).toBe(true));
  });
});
