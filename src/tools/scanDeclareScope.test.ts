/**
 * Unit tests for scan_declare_scope tool.
 *
 * Scope declaration is metadata; failures should never crash the caller.
 * These tests verify:
 *  1. Happy-path body shape matches the backend contract.
 *  2. Required-field validation catches missing agent_id / allowed_tools
 *     before hitting the network.
 *  3. Backend errors surface as { error } without throwing.
 *  4. Optional fields (purpose, forbidden_tools, expires_at,
 *     max_duration_seconds) are only serialized when set — the backend
 *     treats unset fields differently from empty strings.
 *  5. Timeout guard mirrors sessionStatus — a hanging backend must not
 *     block the caller.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanDeclareScope } from './scanDeclareScope.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 50,
    debug: false,
  },
  getAuthHeaders: () => ({ Authorization: 'Bearer test-key' }),
}));

vi.spyOn(console, 'error').mockImplementation(() => {});

describe('scanDeclareScope', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('posts a valid body with only required fields', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        scope_id: 'sc_abc',
        agent_id: 'recon_agent_01',
        allowed_tools: ['read_invoice'],
        forbidden_tools: [],
        active_until: null,
        expired: false,
      }),
    });

    const result = await scanDeclareScope({
      agent_id: 'recon_agent_01',
      allowed_tools: ['read_invoice'],
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://mock-backend.test/api/v1/agent/scope/declare');
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({
      agent_id: 'recon_agent_01',
      allowed_tools: ['read_invoice'],
    });
    expect(result.scope_id).toBe('sc_abc');
    expect(result.error).toBeUndefined();
  });

  it('serializes optional fields only when set', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ scope_id: 'sc_def' }),
    });

    await scanDeclareScope({
      agent_id: 'triage_bot_04',
      purpose: 'invoice reconciliation',
      allowed_tools: ['read_invoice', 'match_ledger_entry'],
      forbidden_tools: ['exec_shell'],
      max_duration_seconds: 28800,
      expires_at: '2026-07-14T23:59:59Z',
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(body).toEqual({
      agent_id: 'triage_bot_04',
      purpose: 'invoice reconciliation',
      allowed_tools: ['read_invoice', 'match_ledger_entry'],
      forbidden_tools: ['exec_shell'],
      max_duration_seconds: 28800,
      expires_at: '2026-07-14T23:59:59Z',
    });
  });

  it('returns an error for missing agent_id without hitting the network', async () => {
    const result = await scanDeclareScope({
      agent_id: '',
      allowed_tools: ['*'],
    });
    expect(result.error).toBe('agent_id is required');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns an error for missing allowed_tools without hitting the network', async () => {
    // @ts-expect-error — deliberately drop the required field to exercise guard
    const result = await scanDeclareScope({ agent_id: 'x' });
    expect(result.error).toBe('allowed_tools is required (use ["*"] to allow any tool)');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('surfaces backend error text as { error } on non-2xx', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: async () => 'expires_at is in the past',
    });

    const result = await scanDeclareScope({
      agent_id: 'stale_scope_agent',
      allowed_tools: ['read_invoice'],
      expires_at: '2020-01-01T00:00:00Z',
    });
    expect(result.error).toBe('expires_at is in the past');
    expect(result.scope_id).toBeUndefined();
  });

  it('falls back to status text when the backend body is empty', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: async () => '',
    });
    const result = await scanDeclareScope({
      agent_id: 'ag',
      allowed_tools: ['*'],
    });
    expect(result.error).toBe('Backend returned 500');
  });

  it('returns a timeout error when fetch aborts', async () => {
    mockFetch.mockImplementationOnce(async (_url: string, init: RequestInit) => {
      await new Promise<void>((_, reject) => {
        init.signal!.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
      // Never reached — abort rejects above.
      throw new Error('unreachable');
    });

    const result = await scanDeclareScope({
      agent_id: 'ag',
      allowed_tools: ['*'],
    });
    expect(result.error).toBe('Request timed out');
  });
});
