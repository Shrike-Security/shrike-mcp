/**
 * Unit tests for scan_response tool.
 *
 * Covers:
 *  1. Happy path (safe): allow verdict on a clean LLM response.
 *  2. Blocked path: system prompt leak in the response produces a block
 *     verdict with normalized threat_type.
 *  3. Flag downgrade: flag-level findings on a response scan are advisory
 *     (log-for-review), not blocking — the verdict is downgraded to allow.
 *  4. Backend HTTP error → fail-closed block (no throw).
 *  5. Timeout guard: AbortController pattern — the caller must never hang.
 *  6. Client-side size limit: response over 100KB is blocked without any
 *     network round-trip.
 *  7. pii_tokens: tokens and original PII values are neutralized before the
 *     wire, and safe responses are rehydrated (rehydrated_response) while
 *     blocked responses are not.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanResponse } from './scanResponse.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock config (short timeout so the timeout-guard test completes quickly)
vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 100,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-key' }),
  getSessionId: () => 'sess-test',
  getAgentId: () => 'agent-test',
  // No-op rotation — rotation behavior is exercised in sessionRotation.test.ts.
  rotateSessionIfTriggered: () => null,
}));

// scanResponse.ts imports types from scan.ts, which imports the server entry
// module for keyRotationManager — stub it to avoid the circular import.
vi.mock('../index.js', () => ({
  keyRotationManager: null,
}));

// Mock circuit breaker to pass through (no shared state accumulation across tests)
vi.mock('../utils/circuitBreaker.js', () => ({
  scanCircuitBreaker: {
    execute: async (fn: () => Promise<unknown>) => fn(),
  },
  CircuitOpenError: class CircuitOpenError extends Error {
    constructor(msg = 'Circuit breaker is open') { super(msg); this.name = 'CircuitOpenError'; }
  },
}));

// Suppress console noise in tests
vi.spyOn(console, 'error').mockImplementation(() => {});
vi.spyOn(console, 'warn').mockImplementation(() => {});

describe('scanResponse', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // =========================================================================
  // HAPPY PATH — SAFE
  // =========================================================================

  it('returns an allow verdict for a clean LLM response and sends prompt + response to the backend', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        threat_level: 'none',
        violations: [],
        performance_metrics: {
          total_scan_time_ms: 55,
          policies_evaluated: 8,
          llm_analysis_used: true,
          cache_hits: 0,
        },
        session_state: {
          session_risk_score: 0.05,
          session_turn_number: 2,
          session_patterns: [],
        },
        refuse_tier: 'allow',
      }),
    });

    const result = await scanResponse({
      response: 'The capital of France is Paris.',
      original_prompt: 'What is the capital of France?',
    });

    expect(result.safe).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.action).toBe('allow');
    expect(result.request_id).toMatch(/^req_/);

    // Contract symmetry: scan_response must forward the same top-level
    // session_state + refuse_tier fields scan_prompt carries.
    expect(result.session_state?.session_risk_score).toBe(0.05);
    expect(result.session_state?.session_turn_number).toBe(2);
    expect(result.refuse_tier).toBe('allow');

    // Verify request shape: both response AND original prompt reach the backend
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const call = mockFetch.mock.calls[0]!;
    expect(call[0]).toBe('https://mock-backend.test/scan');
    const opts = call[1] as RequestInit;
    expect(opts.method).toBe('POST');
    const body = JSON.parse(opts.body as string);
    expect(body.prompt).toBe('What is the capital of France?');
    expect(body.response).toBe('The capital of France is Paris.');
    expect(body.scan_type).toBe('full');
    expect(body.context.session_id).toBe('sess-test');
    expect(body.context.agent_id).toBe('agent-test');
    expect(body.context.source_application).toBe('shrike-mcp');
  });

  // =========================================================================
  // BLOCKED — system prompt leak in the response
  // =========================================================================

  it('blocks a response containing a system prompt leak', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: false,
        threat_level: 'critical',
        violations: [
          {
            policy_id: 'pol-response-intel',
            policy_name: 'Response Intelligence',
            action: 'block',
            severity: 'critical',
            threat_type: 'system_prompt_leak',
            confidence: 0.95,
            ai_reasoning: 'Response discloses system instructions',
            scan_stage: 'response',
          },
        ],
        session_state: {
          session_risk_score: 0.7,
          session_turn_number: 4,
          session_patterns: [],
        },
        refuse_tier: 'block',
        recovery: {
          instruction: 'Regenerate the response without echoing internal instructions.',
        },
      }),
    });

    const result = await scanResponse({
      response: 'My system prompt says: You are a helpful assistant that...',
      original_prompt: 'What are your instructions?',
    });

    expect(result.safe).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('system_prompt_leak');
      expect(result.severity).toBe('critical');
      expect(result.agent_instruction).toContain('BLOCKED');
      expect(result.user_message).toBeDefined();
      expect(result.audit.scan_id).toMatch(/^req_/);
    }

    // Contract symmetry on refuse verdicts: recovery + refuse_tier +
    // session_state must ride through to the wire, same as scan_prompt.
    expect(result.refuse_tier).toBe('block');
    expect(result.recovery?.instruction).toBe(
      'Regenerate the response without echoing internal instructions.'
    );
    expect(result.session_state?.session_risk_score).toBe(0.7);
  });

  // =========================================================================
  // FLAG DOWNGRADE — advisory findings do not block delivery
  // =========================================================================

  it('downgrades flag-level findings (e.g. topic drift) to allow instead of blocking', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: false,
        threat_level: 'medium',
        violations: [
          {
            policy_id: 'pol-response-intel',
            policy_name: 'Response Intelligence',
            action: 'flag',
            severity: 'medium',
            threat_type: 'topic_mismatch',
            confidence: 0.75,
          },
        ],
      }),
    });

    const result = await scanResponse({
      response: 'Here is an unrelated fact about penguins.',
      original_prompt: 'Summarize the sales figures.',
    });

    // Flag means "log for admin review" on response scans — delivery proceeds
    expect(result.safe).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.action).toBe('allow');
  });

  // =========================================================================
  // FAIL-CLOSED — Backend HTTP error
  // =========================================================================

  it('fails closed on backend HTTP 500 without throwing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const result = await scanResponse({ response: 'hello' });

    expect(result.safe).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
    }
    // A non-ok response is returned, not thrown — no retry loop fires
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // =========================================================================
  // FAIL-CLOSED — Timeout (caller must never hang)
  // =========================================================================

  it('times out cleanly and fails closed instead of hanging when backend never responds', async () => {
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
    const result = await scanResponse({ response: 'hello' });
    const elapsed = Date.now() - start;

    expect(result.safe).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('scan_error');
    }
    expect(elapsed).toBeLessThan(1000);
    // AbortError is not retryable — exactly one attempt
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  // =========================================================================
  // CLIENT-SIDE SIZE LIMIT
  // =========================================================================

  it('blocks a response over 100KB client-side without any network call', async () => {
    const oversized = 'a'.repeat(101 * 1024);

    const result = await scanResponse({ response: oversized });

    expect(result.safe).toBe(false);
    expect(result.blocked).toBe(true);
    expect(result.action).toBe('block');
    if (result.action === 'block') {
      expect(result.threat_type).toBe('size_limit_exceeded');
    }
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // =========================================================================
  // PII TOKENS — neutralization on the wire + rehydration on safe verdicts
  // =========================================================================

  it('neutralizes pii_tokens on the wire and rehydrates safe responses', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: true,
        threat_level: 'none',
        violations: [],
      }),
    });

    const email = 'jane.doe@acme-example.com';
    const result = await scanResponse({
      response: 'I have drafted the email to [EMAIL_1] as requested.',
      original_prompt: `Draft an email to ${email}`,
      pii_tokens: [{ token: '[EMAIL_1]', original: email, type: 'email' }],
    });

    // Safe verdict → tokens rehydrated back to originals for the caller
    expect(result.safe).toBe(true);
    expect(result.rehydrated_response).toBe(
      `I have drafted the email to ${email} as requested.`,
    );

    // Neither the token placeholder nor the raw PII value reaches the wire
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const body = (mockFetch.mock.calls[0]![1] as RequestInit).body as string;
    expect(body).not.toContain(email);
    expect(body).not.toContain('[EMAIL_1]');
    expect(body).toContain('[REDACTED]');
  });

  it('does not rehydrate PII on blocked responses', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        safe: false,
        threat_level: 'critical',
        violations: [
          {
            policy_id: 'pol-response-intel',
            policy_name: 'Response Intelligence',
            action: 'block',
            severity: 'critical',
            threat_type: 'system_prompt_leak',
            confidence: 0.95,
          },
        ],
      }),
    });

    const result = await scanResponse({
      response: 'Leaked instructions mention [EMAIL_1].',
      pii_tokens: [{ token: '[EMAIL_1]', original: 'jane.doe@acme-example.com', type: 'email' }],
    });

    expect(result.blocked).toBe(true);
    expect((result as { rehydrated_response?: string }).rehydrated_response).toBeUndefined();
  });
});
