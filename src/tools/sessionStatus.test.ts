/**
 * Unit tests for session_status tool.
 *
 * session_status is listed in the recovery.available_tools array on any
 * session_locked verdict. These tests verify:
 *  1. Happy path: backend response is passed through verbatim so wire-shape
 *     drift between backend + SDK gets caught here rather than in prod.
 *  2. Timeout guard mirrors reset_session — quarantined callers must never
 *     hang. If the backend takes forever, the caller gets a clean error.
 *  3. Missing session (exists=false) surfaces without crashing.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { sessionStatus } from './sessionStatus.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 100,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
  getSessionId: () => 'sess-test',
  getAgentId: () => 'agent-test',
}));

vi.spyOn(console, 'error').mockImplementation(() => {});

describe('sessionStatus', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('passes through a happy-path locked-session response verbatim', async () => {
    const canonicalInstruction =
      'Start a new session_id for the next call. This session has ' +
      'accumulated risk from prior turns that cannot be scanned out; ' +
      'a fresh session_id is the self-service recovery path. ' +
      'reset_session is administratively restricted at the block threshold.';
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        exists: true,
        session_id: 'sess-test',
        agent_id: 'agent-test',
        session_risk_score: 0.9,
        session_turn_number: 6,
        session_locked: true,
        refuse_tier: 'block',
        session_patterns: ['multi_turn_reconnaissance', 'multi_turn_crescendo'],
        first_scan_at: '2026-07-06T15:00:00.000Z',
        last_scan_at: '2026-07-06T15:10:00.000Z',
        expires_at: '2026-07-06T17:10:00.000Z',
        recovery: {
          instruction: canonicalInstruction,
          available_tools: ['scan_prompt', 'scan_response', 'session_status'],
        },
      }),
    });

    const result = await sessionStatus({});

    expect(result.exists).toBe(true);
    expect(result.session_locked).toBe(true);
    expect(result.refuse_tier).toBe('block');
    expect(result.session_risk_score).toBe(0.9);
    expect(result.recovery?.instruction).toBe(canonicalInstruction);
    expect(result.recovery?.available_tools).toEqual([
      'scan_prompt', 'scan_response', 'session_status',
    ]);
    expect(result.error).toBeUndefined();
  });

  it('returns exists=false without recovery block when the session is not cached', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        exists: false,
        session_id: 'sess-test',
        agent_id: 'agent-test',
      }),
    });

    const result = await sessionStatus({});

    expect(result.exists).toBe(false);
    expect(result.recovery).toBeUndefined();
    expect(result.session_risk_score).toBeUndefined();
    expect(result.session_locked).toBeUndefined();
  });

  it('surfaces backend HTTP errors as exists=false + error field', async () => {
    mockFetch.mockResolvedValueOnce({ ok: false, status: 401 });

    const result = await sessionStatus({});

    expect(result.exists).toBe(false);
    expect(result.error).toContain('401');
  });

  it('sends session_id + agent_id as query params', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ exists: false, session_id: 'x', agent_id: 'y' }),
    });

    await sessionStatus({ session_id: 'x', agent_id: 'y' });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const call = mockFetch.mock.calls[0]!;
    const url = call[0] as string;
    expect(url).toContain('/api/session/status');
    expect(url).toContain('session_id=x');
    expect(url).toContain('agent_id=y');
    const opts = call[1] as RequestInit;
    expect(opts.method).toBe('GET');
  });

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
      });
    });

    const start = Date.now();
    const result = await sessionStatus({});
    const elapsed = Date.now() - start;

    expect(result.exists).toBe(false);
    expect(result.error).toBe('Request timed out');
    expect(elapsed).toBeLessThan(1000);
  });
});
