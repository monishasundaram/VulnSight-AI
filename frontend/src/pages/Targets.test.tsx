import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Targets from './Targets';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('authorized target workspace', () => {
  it('displays API-backed target metadata and links to exact scan and finding scopes', async () => {
    const target = {
      id: 'target-7', name: 'Authorized fixture', base_url: 'https://fixture.example/',
      owner_reference: 'AUTH-42', authorization_status: 'authorized',
      allowed_hostnames: ['fixture.example'], scope_notes: 'Public HTTPS only', enabled: true,
      last_scan_at: '2026-10-22T10:00:00+00:00',
    };
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ items: [target], total: 1 }), { status: 200, headers: { 'Content-Type': 'application/json' } })));
    render(<MemoryRouter><Targets /></MemoryRouter>);

    expect(await screen.findByRole('heading', { name: 'Authorized fixture' })).toBeInTheDocument();
    expect(screen.getByText('AUTH-42')).toBeInTheDocument();
    expect(screen.getByText('authorized')).toBeInTheDocument();
    expect(screen.getByText('Last scan')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View scans' })).toHaveAttribute('href', '/scans?target_id=target-7');
    expect(screen.getByRole('link', { name: 'Review findings' })).toHaveAttribute('href', '/findings?target_id=target-7');
  });
});
