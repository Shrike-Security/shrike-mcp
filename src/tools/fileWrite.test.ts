/**
 * Unit tests for scan_file_write tool
 * Tests safe writes (two-request path + content scan), blocked writes,
 * fail-closed behavior, timeout guard, client-side size limit, and
 * session-quarantine (session_locked) pass-through.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanFileWrite } from './fileWrite.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock config — scanTimeoutMs kept short so the timeout test fails fast.
vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 100,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
  getSessionId: () => 'test-session',
  getAgentId: () => 'test-agent',
  // No-op rotation for these mocked-response tests; rotation is exercised
  // explicitly in sessionRotation.test.ts against the real config.
  rotateSessionIfTriggered: () => null,
}));

// Mock circuit breaker to pass through (no state accumulation across tests)
vi.mock('../utils/circuitBreaker.js', () => ({
  scanCircuitBreaker: {
    execute: async (fn: () => Promise<unknown>) => fn(),
  },
  CircuitOpenError: class CircuitOpenError extends Error {
    constructor(msg = 'Circuit breaker is open') { super(msg); this.name = 'CircuitOpenError'; }
  },
}));

// Suppress console.error/warn in tests
vi.spyOn(console, 'error').mockImplementation(() => {});
vi.spyOn(console, 'warn').mockImplementation(() => {});

/** Convenience: a safe backend verdict for one of the two scan legs. */
function safeLeg(contentType: 'file_path' | 'file_content', extra: Record<string, unknown> = {}) {
  return {
    ok: true,
    json: async () => ({
      safe: true,
      confidence: 1.0,
      content_type: contentType,
      scan_time_ms: 4,
      ...extra,
    }),
  };
}

describe('scanFileWrite', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // SAFE WRITES — path scan + content scan (two backend calls)
  // =========================================================================

  it('should allow safe writes after scanning both path and content', async () => {
    mockFetch
      .mockResolvedValueOnce(safeLeg('file_path'))
      .mockResolvedValueOnce(safeLeg('file_content', {
        refuse_tier: 'allow',
        session_state: {
          session_risk_score: 0.05,
          session_turn_number: 2,
          session_patterns: [],
        },
      }));

    const result = await scanFileWrite({
      path: '/app/output/report.txt',
      content: 'Quarterly summary: all systems nominal.',
    });

    expect(result.safe).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.action).toBe('allow');
    expect(result.content_type).toBe('file_content');
    expect(result.refuse_tier).toBe('allow');
    expect(result.session_state?.session_turn_number).toBe(2);
    expect(result.request_id).toMatch(/^req_/);

    // Two backend calls: one for the path, one for the content
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const pathBody = JSON.parse((mockFetch.mock.calls[0][1] as any).body);
    expect(pathBody.content).toBe('/app/output/report.txt');
    expect(pathBody.content_type).toBe('file_path');
    expect(pathBody.context.session_id).toBe('test-session');
    expect(pathBody.context.source_application).toBe('shrike-mcp');

    const contentBody = JSON.parse((mockFetch.mock.calls[1][1] as any).body);
    expect(contentBody.content_type).toBe('file_content');
    expect(contentBody.context.content).toBe('Quarterly summary: all systems nominal.');
    expect(contentBody.context.session_id).toBe('test-session');
  });

  // =========================================================================
  // BLOCKED WRITES — content violation
  // =========================================================================

  it('should block when the content scan reports a secrets violation', async () => {
    mockFetch
      .mockResolvedValueOnce(safeLeg('file_path'))
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          safe: false,
          threat_type: 'secrets_exposure',
          severity: 'critical',
          reason: 'API key pattern detected in file content',
          confidence: 0.97,
          content_type: 'file_content',
          scan_time_ms: 6,
          refuse_tier: 'block',
        }),
      });

    const result = await scanFileWrite({
      path: '/app/config/settings.json',
      content: 'api_key = "example-secret-value"',
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('secrets_exposure');
      expect(result.owasp_category).toBe('LLM02');
      expect(result.severity).toBe('critical');
      expect(result.confidence).toBe('high');
      expect(result.guidance).toBeDefined();
      expect(result.agent_instruction).toContain('BLOCKED');
      expect(result.user_message).toBeDefined();
      expect(result.refuse_tier).toBe('block');
      expect(result.audit.scan_id).toMatch(/^req_/);
    }
  });

  it('should block when the path scan reports a traversal violation', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          safe: false,
          threat_type: 'path_traversal',
          severity: 'high',
          reason: 'Path escapes the allowed directory scope',
          confidence: 0.9,
          content_type: 'file_path',
          scan_time_ms: 3,
        }),
      })
      .mockResolvedValueOnce(safeLeg('file_content'));

    const result = await scanFileWrite({
      path: '../../etc/passwd',
      content: 'harmless text',
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('path_traversal');
      expect(result.severity).toBe('high');
    }
  });

  // =========================================================================
  // CLIENT-SIDE SIZE LIMIT — short-circuits before any backend call
  // =========================================================================

  it('should block oversized content client-side without calling the backend', async () => {
    const oversized = 'a'.repeat(1024 * 1024 + 1); // just over the 1MB limit

    const result = await scanFileWrite({
      path: '/app/output/huge.txt',
      content: oversized,
    });

    expect(mockFetch).not.toHaveBeenCalled();
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('size_limit_exceeded');
    }
  });

  // =========================================================================
  // SESSION QUARANTINE (act plane) — session_locked pass-through
  // =========================================================================

  it('should surface a session_locked verdict with the recovery instruction verbatim', async () => {
    const recoveryInstruction =
      'Start a new session_id for the next call. This session has ' +
      'accumulated risk from prior turns that cannot be scanned out; ' +
      'a fresh session_id is the self-service recovery path. ' +
      'reset_session is administratively restricted at the block threshold.';

    const lockedLeg = {
      ok: true,
      json: async () => ({
        safe: false,
        threat_type: 'session_locked',
        severity: 'critical',
        reason: 'Session quarantined: accumulated risk crossed threshold',
        confidence: 1.0,
        content_type: 'file_path',
        scan_time_ms: 2,
        refuse_tier: 'block',
        recovery: {
          instruction: recoveryInstruction,
          available_tools: ['scan_prompt', 'scan_response', 'session_status'],
        },
        session_state: {
          session_risk_score: 0.92,
          session_turn_number: 7,
          session_patterns: ['multi_turn_crescendo'],
          session_locked: true,
        },
      }),
    };
    // Both legs report the same session-level verdict
    mockFetch.mockResolvedValueOnce(lockedLeg).mockResolvedValueOnce(lockedLeg);

    const result = await scanFileWrite({
      path: '/app/output/notes.txt',
      content: 'anything',
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('session_locked');
      expect(result.recovery?.instruction).toBe(recoveryInstruction);
      expect(result.recovery?.available_tools).toEqual([
        'scan_prompt', 'scan_response', 'session_status',
      ]);
      expect(result.session_state?.session_locked).toBe(true);
    }
  });

  // =========================================================================
  // FAIL-CLOSED — Backend error
  // =========================================================================

  it('should block on backend error (fail-closed) without throwing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await scanFileWrite({
      path: '/app/output/report.txt',
      content: 'hello',
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
      expect(result.agent_instruction).toContain('BLOCKED');
    }
  });

  it('should block when the content-scan leg errors after a safe path scan', async () => {
    mockFetch
      .mockResolvedValueOnce(safeLeg('file_path'))
      .mockResolvedValueOnce({ ok: false, status: 500 });

    const result = await scanFileWrite({
      path: '/app/output/report.txt',
      content: 'hello',
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
    }
  });

  // =========================================================================
  // FAIL-CLOSED — Backend timeout (AbortError)
  // =========================================================================

  it('should block on timeout quickly instead of hanging (fail-closed)', async () => {
    mockFetch.mockImplementationOnce((_url: string, options: RequestInit) => {
      return new Promise((_resolve, reject) => {
        options.signal?.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      });
    });

    const start = Date.now();
    const result = await scanFileWrite({
      path: '/app/output/report.txt',
      content: 'hello',
    });
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1000);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
    }
  });
});
