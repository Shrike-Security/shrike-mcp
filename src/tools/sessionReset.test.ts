/**
 * Unit tests for reset_session tool.
 *
 * The 2026-07-01 launch-test report flagged intermittent hangs on
 * reset_session (and check_approval). Root cause: fetch() had no
 * AbortController, so a stuck backend or held correlator lock left
 * the MCP client hanging indefinitely with no error the caller could
 * react to. The timeout-guard test below locks in the fix.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { resetSession } from './sessionReset.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 100, // Fast timeout for test — real default is 15s.
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
  getSessionId: () => 'sess-test',
  getAgentId: () => 'agent-test',
}));

vi.spyOn(console, 'error').mockImplementation(() => {});

describe('resetSession', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns success when backend acknowledges the reset', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ success: true, session_id: 'sess-test' }),
    });

    const result = await resetSession({ reason: 'unit test' });

    expect(result.success).toBe(true);
    expect(result.session_id).toBe('sess-test');
    expect(result.error).toBeUndefined();
  });

  it('surfaces backend HTTP errors instead of hanging', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await resetSession({});

    expect(result.success).toBe(false);
    expect(result.error).toContain('500');
  });

  // The fix under test: without a timeout guard, this test would hang
  // until vitest's default timeout kills the test. With the guard, the
  // AbortController fires at scanTimeoutMs (100ms in the mock) and the
  // resetSession returns a clean timeout error the caller can react to.
  it('times out cleanly instead of hanging when backend never responds', async () => {
    mockFetch.mockImplementationOnce((_url: string, options: RequestInit) => {
      return new Promise((_resolve, reject) => {
        const signal = options.signal;
        if (signal) {
          signal.addEventListener('abort', () => {
            const err = new Error('The operation was aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }
        // Never resolve — simulate a backend that hangs forever.
      });
    });

    const start = Date.now();
    const result = await resetSession({});
    const elapsed = Date.now() - start;

    expect(result.success).toBe(false);
    expect(result.message).toContain('timed out');
    expect(result.error).toBe('Request timed out');
    // Should return within ~100ms + noise, definitely not the default 15s.
    expect(elapsed).toBeLessThan(1000);
  });
});
