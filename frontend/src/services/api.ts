export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export const SESSION_EXPIRED_EVENT = 'vulnsight:session-expired';

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function getCsrfToken() {
  return csrfToken;
}

function safeValidationMessage(detail: unknown): string | undefined {
  if (!Array.isArray(detail)) return undefined;
  const fields = new Map<string, string>();
  for (const issue of detail) {
    if (!issue || typeof issue !== 'object') continue;
    const record = issue as { loc?: unknown; type?: unknown };
    if (!Array.isArray(record.loc)) continue;
    const field = [...record.loc].reverse().find((part): part is string => typeof part === 'string');
    if (field !== 'email' && field !== 'password') continue;
    fields.set(field, typeof record.type === 'string' ? record.type : 'invalid');
  }
  const messages: string[] = [];
  if (fields.has('email')) messages.push('Enter a valid email address.');
  if (fields.has('password')) {
    const type = fields.get('password');
    messages.push(type === 'string_too_short' ? 'Password must be at least 12 characters.' :
      type === 'string_too_long' ? 'Password must be no more than 128 characters.' : 'Check your password and try again.');
  }
  return messages.length ? messages.join(' ') : 'Please check the form details and try again.';
}

export async function apiRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  if (!path.startsWith('/api/')) throw new Error('API paths must be same-origin /api/ routes');
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const method = (init.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS' && csrfToken) headers.set('X-CSRF-Token', csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: 'include', redirect: 'error' });
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/api/auth/') && typeof window !== 'undefined') {
      window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
    }
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json() as { detail?: unknown; message?: unknown };
      const detail = typeof body.detail === 'string' ? body.detail : typeof body.message === 'string' ? body.message : safeValidationMessage(body.detail);
      if (detail && detail.length <= 240) message = detail;
    } catch { /* Keep the safe status-only message. */ }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

export function userFacingError(error: unknown, fallback = 'Something went wrong. Please try again.') {
  if (error instanceof ApiError) {
    if (error.status === 401 && (error.message === 'Authentication required' || /^Request failed \(401\)$/.test(error.message))) {
      return 'Your session expired or is no longer valid. Please sign in again.';
    }
    if (error.status === 403) return 'This action is not permitted for your account.';
    if (error.status >= 500) return 'The service is temporarily unavailable. Please try again shortly.';
    return error.message;
  }
  return fallback;
}
