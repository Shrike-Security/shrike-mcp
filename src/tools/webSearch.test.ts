/**
 * Unit tests for scan_web_search tool
 * Tests safe queries, blocked queries, client-side domain checks,
 * fail-closed behavior, timeout guard, and session-quarantine
 * (session_locked) pass-through.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanWebSearch } from './webSearch.js';

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

describe('scanWebSearch', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // SAFE QUERIES
  // =========================================================================

  it('should allow safe queries and surface the symmetric contract fields', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        confidence: 1.0,
        content_type: 'web_search',
        scan_time_ms: 6,
        refuse_tier: 'allow',
        session_state: {
          session_risk_score: 0.0,
          session_turn_number: 1,
          session_patterns: [],
        },
      }),
    });

    const result = await scanWebSearch({ query: 'best practices for API rate limiting' });

    expect(result.safe).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.action).toBe('allow');
    expect(result.content_type).toBe('web_search');
    expect(result.refuse_tier).toBe('allow');
    expect(result.session_state?.session_turn_number).toBe(1);
    expect(result.request_id).toMatch(/^req_/);

    // Verify backend was called correctly
    expect(mockFetch).toHaveBeenCalledWith(
      'https://mock-backend.test/api/scan/specialized',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          content: 'best practices for API rate limiting',
          content_type: 'web_search',
          context: {
            session_id: 'test-session',
            agent_id: 'test-agent',
            parent_agent_id: '',
            task_chain: '',
            source_application: 'shrike-mcp',
          },
        }),
      }),
    );
  });

  it('should forward target domains to the backend as metadata', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        confidence: 1.0,
        content_type: 'web_search',
        scan_time_ms: 5,
      }),
    });

    await scanWebSearch({
      query: 'kubernetes ingress documentation',
      targetDomains: ['kubernetes.io'],
    });

    const body = JSON.parse((mockFetch.mock.calls[0][1] as any).body);
    expect(body.metadata).toEqual({ target_domains: ['kubernetes.io'] });
  });

  // =========================================================================
  // BLOCKED QUERIES — backend verdict
  // =========================================================================

  it('should block queries the backend flags as data exfiltration', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: false,
        threat_type: 'data_exfiltration',
        severity: 'critical',
        reason: 'Query contains credential-hunting patterns',
        confidence: 0.93,
        content_type: 'web_search',
        scan_time_ms: 8,
        refuse_tier: 'block',
      }),
    });

    const result = await scanWebSearch({ query: 'site:example.com filetype:env DB_PASSWORD' });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('data_exfiltration');
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

  // =========================================================================
  // BLOCKED QUERIES — client-side domain checks (supplementary to backend)
  // =========================================================================

  it('should block a blocked-list target domain even when the backend says safe', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        confidence: 1.0,
        content_type: 'web_search',
        scan_time_ms: 5,
      }),
    });

    const result = await scanWebSearch({
      query: 'paste service',
      targetDomains: ['pastebin.com'],
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('blocked_domain');
      expect(result.severity).toBe('high');
    }
  });

  it('should block domains with suspicious keywords', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        confidence: 1.0,
        content_type: 'web_search',
        scan_time_ms: 5,
      }),
    });

    const result = await scanWebSearch({
      query: 'software download',
      targetDomains: ['free-keygen-downloads.example.com'],
    });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      // suspicious_domain normalizes to the blocked_domain category
      expect(result.threat_type).toBe('blocked_domain');
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

    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: false,
        threat_type: 'session_locked',
        severity: 'critical',
        reason: 'Session quarantined: accumulated risk crossed threshold',
        confidence: 1.0,
        content_type: 'web_search',
        scan_time_ms: 2,
        refuse_tier: 'block',
        recovery: {
          instruction: recoveryInstruction,
          available_tools: ['scan_prompt', 'scan_response', 'session_status'],
        },
        session_state: {
          session_risk_score: 0.88,
          session_turn_number: 5,
          session_patterns: ['multi_turn_crescendo'],
          session_locked: true,
        },
      }),
    });

    const result = await scanWebSearch({ query: 'weather today' });

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

    const result = await scanWebSearch({ query: 'harmless query' });

    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
      expect(result.agent_instruction).toContain('BLOCKED');
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
    const result = await scanWebSearch({ query: 'harmless query' });
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(1000);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
    }
  });
});
