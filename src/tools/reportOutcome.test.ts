/**
 * Unit tests for report_outcome.
 *
 * The tool closes the loop a scan opens, so the failure that matters is a
 * report that changes the agent's behaviour. These verify:
 *  1. The wire body is what /api/scan/outcome accepts, and carries no error text.
 *  2. The timeout guard: a hung backend returns a clean result, never a hang.
 *  3. 404 and 409 are reported, not thrown, and not retried.
 *  4. Bad input never reaches the network.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportOutcome } from './reportOutcome.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 100,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
}));

describe('reportOutcome', () => {
  beforeEach(() => mockFetch.mockReset());
  afterEach(() => vi.restoreAllMocks());

  it('posts the shape /api/scan/outcome accepts', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'recorded', held: true }),
    });

    const result = await reportOutcome({ scan_id: 'scan_abc', outcome: 'executed', exit_status: 0 });

    expect(result).toEqual({
      recorded: true,
      scan_id: 'scan_abc',
      outcome: 'executed',
      status: 'recorded',
      held: true,
    });

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://mock-backend.test/api/scan/outcome');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body);
    expect(body.scan_id).toBe('scan_abc');
    expect(body.outcome).toBe('executed');
    expect(body.exit_status).toBe(0);
    expect(body.source).toBe('shrike-mcp');
    expect(typeof body.ran_at).toBe('string');
  });

  it('omits exit_status when it is not an integer, and never sends error text', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'recorded', held: false }) });

    await reportOutcome({ scan_id: 'scan_abc', outcome: 'failed' });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body).not.toHaveProperty('exit_status');
    // The backend's own contract: this path carries a status and a time only.
    expect(Object.keys(body).sort()).toEqual(['outcome', 'ran_at', 'scan_id', 'source']);
  });

  it('returns a clean result when the backend hangs, rather than hanging', async () => {
    mockFetch.mockImplementationOnce((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      })
    );

    const result = await reportOutcome({ scan_id: 'scan_abc', outcome: 'executed' });

    expect(result.recorded).toBe(false);
    expect(result.error).toBe('Request timed out');
  });

  it('surfaces not_found without throwing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ status: 'not_found', scan_id: 'scan_missing' }),
    });

    const result = await reportOutcome({ scan_id: 'scan_missing', outcome: 'executed' });

    expect(result.recorded).toBe(false);
    expect(result.status).toBe('not_found');
    expect(result.error).toContain('404');
  });

  it('surfaces already_closed: the first answer is the record', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({ status: 'already_closed', held: true }),
    });

    const result = await reportOutcome({ scan_id: 'scan_abc', outcome: 'skipped' });

    expect(result.recorded).toBe(false);
    expect(result.status).toBe('already_closed');
    expect(result.held).toBe(true);
  });

  it('rejects bad input without touching the network', async () => {
    const noId = await reportOutcome({ scan_id: '  ', outcome: 'executed' });
    expect(noId.recorded).toBe(false);
    expect(noId.error).toBe('scan_id is required');

    const badOutcome = await reportOutcome({ scan_id: 'scan_abc', outcome: 'ran' as never });
    expect(badOutcome.recorded).toBe(false);
    expect(badOutcome.error).toContain('executed, failed or skipped');

    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('does not throw when the backend returns a non-JSON body', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => { throw new Error('not json'); },
    });

    const result = await reportOutcome({ scan_id: 'scan_abc', outcome: 'executed' });
    expect(result.recorded).toBe(true);
    expect(result.status).toBeUndefined();
  });
});
