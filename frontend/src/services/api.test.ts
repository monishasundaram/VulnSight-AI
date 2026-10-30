import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequest } from './api';

afterEach(() => { vi.unstubAllGlobals(); });

describe('API validation error messages', () => {
  it('explains the registration password minimum without echoing submitted values', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      detail: [{
        type: 'string_too_short',
        loc: ['body', 'password'],
        msg: 'String should have at least 12 characters',
        input: 'PRIVATE-TEST-PASSWORD',
      }],
    }), { status: 422, headers: { 'Content-Type': 'application/json' } })));

    const error = await apiRequest('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'test@example.com', password: 'PRIVATE-TEST-PASSWORD' }),
    }).catch((reason: unknown) => reason);
    expect(error).toMatchObject({ message: 'Password must be at least 12 characters.' });
    expect((error as Error).message).not.toContain('PRIVATE-TEST-PASSWORD');
  });
});
