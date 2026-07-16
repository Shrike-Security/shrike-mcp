/**
 * Contract test: symmetric session_state block on the sanitized wire response.
 *
 * This test defends the customer contract that every scan response — safe or
 * blocked, observe-plane or act-plane — carries a top-level `session_state`
 * block whenever the caller supplied session identity. Integrators depend on
 * this to build governance policies (auto-rotate above a risk threshold,
 * escalate at turn N, cross-agent supervision) without inspecting tool-
 * specific side-channels. See the symmetric-contract principle.
 *
 * Symmetry properties pinned here:
 *
 *   1. session_state surfaces top-level (NOT nested inside audit) on both
 *      allowed and blocked responses from sanitizeScanResult.
 *   2. session_state surfaces top-level on both allowed and blocked responses
 *      from every specialized sanitizer (SQL, command, file, web, a2a, card).
 *   3. session_state is absent when the source result has no sessionState
 *      (caller supplied no session identity).
 *   4. session_state.session_patterns is always an array (never omitted),
 *      even when empty — JSON contract for integrator loops that iterate.
 *
 * The observable check is the block appearing on both branches of every
 * sanitizer — the earlier bug this fix closes was the block only surfacing
 * on anomaly-detected turns, which stopped integrators from watching the
 * risk score climb through safe turns.
 */

import { describe, it, expect } from 'vitest';
import {
  sanitizeScanResult,
  sanitizeSQLResult,
  sanitizeCommandResult,
  sanitizeFileWriteResult,
  sanitizeWebSearchResult,
  sanitizeA2AMessageResult,
  sanitizeAgentCardResult,
  type SessionState,
} from './responseFormatter.js';

const SAMPLE_STATE: SessionState = {
  session_risk_score: 0.42,
  session_turn_number: 3,
  session_patterns: ['multi_turn_escalation'],
};

const EMPTY_PATTERNS_STATE: SessionState = {
  session_risk_score: 0.0,
  session_turn_number: 1,
  session_patterns: [],
};

// -----------------------------------------------------------------------
// sanitizeScanResult (scan_prompt, scan_response) — observe plane
// -----------------------------------------------------------------------

describe('symmetric session_state on general scan responses', () => {
  it('surfaces session_state top-level on ALLOWED response', () => {
    const result = sanitizeScanResult(
      {
        safe: true,
        threatLevel: 'none',
        confidence: 1.0,
        recommendedAction: 'allow',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: SAMPLE_STATE,
      },
      'req-observe-allow-1',
      'scan_prompt',
    );
    expect(result.blocked).toBe(false);
    expect((result as any).session_state).toEqual(SAMPLE_STATE);
    // Regression guard: session state must NOT live inside audit.
    expect((result as any).audit).not.toHaveProperty('session_risk_score');
    expect((result as any).audit).not.toHaveProperty('correlation_patterns');
  });

  it('surfaces session_state top-level on BLOCKED response', () => {
    const result = sanitizeScanResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block',
        violations: [{
          threatType: 'prompt_injection', severity: 'high', confidence: 0.9,
          action: 'block', policyId: 'p1', policyName: 'Security Policy',
          detectedBy: 'test', message: 'test',
        }],
        summary: { totalViolations: 1, criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, blockedCount: 1 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: SAMPLE_STATE,
      },
      'req-observe-block-1',
      'scan_prompt',
    );
    expect(result.blocked).toBe(true);
    expect((result as any).session_state).toEqual(SAMPLE_STATE);
    expect((result as any).audit).not.toHaveProperty('session_risk_score');
  });

  it('OMITS session_state when no sessionState provided (no session identity)', () => {
    const result = sanitizeScanResult(
      {
        safe: true,
        threatLevel: 'none',
        confidence: 1.0,
        recommendedAction: 'allow',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        // no sessionState field
      },
      'req-no-session',
      'scan_prompt',
    );
    expect((result as any).session_state).toBeUndefined();
  });

  it('carries session_state with empty patterns array on very first turn', () => {
    const result = sanitizeScanResult(
      {
        safe: true,
        threatLevel: 'none',
        confidence: 1.0,
        recommendedAction: 'allow',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: EMPTY_PATTERNS_STATE,
      },
      'req-first-turn',
      'scan_prompt',
    );
    const state = (result as any).session_state as SessionState;
    expect(state.session_turn_number).toBe(1);
    expect(state.session_risk_score).toBe(0.0);
    expect(Array.isArray(state.session_patterns)).toBe(true);
    expect(state.session_patterns).toHaveLength(0);
  });
});

// -----------------------------------------------------------------------
// Specialized sanitizers — act plane
// -----------------------------------------------------------------------

type SpecializedSanitizer = (result: any, requestId: string, toolName?: string) => any;

const SPECIALIZED: Array<[string, SpecializedSanitizer, string]> = [
  ['sanitizeSQLResult', sanitizeSQLResult, 'scan_sql_query'],
  ['sanitizeCommandResult', sanitizeCommandResult, 'scan_command'],
  ['sanitizeFileWriteResult', sanitizeFileWriteResult, 'scan_file_write'],
  ['sanitizeWebSearchResult', sanitizeWebSearchResult, 'scan_web_search'],
  ['sanitizeA2AMessageResult', sanitizeA2AMessageResult, 'scan_a2a_message'],
  ['sanitizeAgentCardResult', sanitizeAgentCardResult, 'scan_agent_card'],
];

function makeSpecializedResult(safe: boolean, sessionState?: SessionState) {
  return {
    safe,
    threatLevel: safe ? 'none' : 'high',
    confidence: safe ? 1.0 : 0.9,
    recommendedAction: safe ? 'allow' : 'block',
    issues: safe ? [] : [{ type: 'test_threat', severity: 'high', message: 'test' }],
    metadata: { scanTimeMs: 1 },
    ...(sessionState ? { sessionState } : {}),
  };
}

describe('symmetric session_state on specialized (act-plane) scan responses', () => {
  for (const [name, sanitizer, toolName] of SPECIALIZED) {
    describe(name, () => {
      it('surfaces session_state top-level on ALLOWED response', () => {
        const result = sanitizer(makeSpecializedResult(true, SAMPLE_STATE), `req-${toolName}-allow`, toolName);
        expect(result.blocked).toBe(false);
        expect(result.session_state).toEqual(SAMPLE_STATE);
        // Regression guard: session state must NOT live inside audit.
        expect(result.audit).not.toHaveProperty('session_risk_score');
      });

      it('surfaces session_state top-level on BLOCKED response', () => {
        const result = sanitizer(makeSpecializedResult(false, SAMPLE_STATE), `req-${toolName}-block`, toolName);
        expect(result.blocked).toBe(true);
        expect(result.session_state).toEqual(SAMPLE_STATE);
      });

      it('OMITS session_state when no sessionState provided', () => {
        const result = sanitizer(makeSpecializedResult(true), `req-${toolName}-nosession`, toolName);
        expect(result.session_state).toBeUndefined();
      });
    });
  }
});

// -----------------------------------------------------------------------
// Approval branch symmetry — the third response type must carry the block
// too. Regression guard for the 2026-07-03 defect Claude Code caught:
// buildApprovalResponse omitted session_state, breaking policy code like
// `if (r.session_state.session_risk_score > threshold)` on the response
// branch most likely to hit the threshold.
// -----------------------------------------------------------------------

describe('symmetric session_state on require_approval responses', () => {
  const APPROVAL_INFO = {
    requires_approval: true,
    approval_id: 'appr-test-123',
    approval_level: 'high',
    action_summary: 'Test action requiring approval',
    policy_name: 'Test Policy',
    expires_in_seconds: 1800,
  };

  it('surfaces session_state top-level on require_approval from sanitizeScanResult', () => {
    const result = sanitizeScanResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.9,
        recommendedAction: 'block',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        approvalInfo: APPROVAL_INFO,
        sessionState: SAMPLE_STATE,
      },
      'req-approval-observe',
      'scan_prompt',
    );
    expect((result as any).action).toBe('require_approval');
    expect((result as any).session_state).toEqual(SAMPLE_STATE);
  });

  it.each([
    ['sanitizeSQLResult', sanitizeSQLResult, 'scan_sql_query'],
    ['sanitizeCommandResult', sanitizeCommandResult, 'scan_command'],
    ['sanitizeFileWriteResult', sanitizeFileWriteResult, 'scan_file_write'],
    ['sanitizeWebSearchResult', sanitizeWebSearchResult, 'scan_web_search'],
    ['sanitizeA2AMessageResult', sanitizeA2AMessageResult, 'scan_a2a_message'],
    ['sanitizeAgentCardResult', sanitizeAgentCardResult, 'scan_agent_card'],
  ] as Array<[string, SpecializedSanitizer, string]>)(
    'surfaces session_state on require_approval from %s',
    (_name, sanitizer, toolName) => {
      const result = sanitizer(
        {
          ...makeSpecializedResult(false, SAMPLE_STATE),
          approvalInfo: APPROVAL_INFO,
        },
        `req-approval-${toolName}`,
        toolName,
      );
      expect(result.action).toBe('require_approval');
      expect(result.session_state).toEqual(SAMPLE_STATE);
    },
  );

  it('OMITS session_state on require_approval when caller had no session identity', () => {
    const result = sanitizeScanResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.9,
        recommendedAction: 'block',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        approvalInfo: APPROVAL_INFO,
        // no sessionState — caller supplied no session identity
      },
      'req-approval-nosession',
      'scan_prompt',
    );
    expect((result as any).action).toBe('require_approval');
    expect((result as any).session_state).toBeUndefined();
  });
});

// -----------------------------------------------------------------------
// Cross-cutting: the audit block no longer carries session-state fields
// -----------------------------------------------------------------------

describe('AuditBlock no longer carries session_state fields (breaking change from 3.x)', () => {
  it('sanitizeScanResult ALLOWED audit has NO session_risk_score / correlation_patterns', () => {
    const result = sanitizeScanResult(
      {
        safe: true,
        threatLevel: 'none',
        confidence: 1.0,
        recommendedAction: 'allow',
        violations: [],
        summary: { totalViolations: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, blockedCount: 0 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: SAMPLE_STATE,
      },
      'req-audit-shape-allow',
      'scan_prompt',
    );
    expect(Object.keys((result as any).audit)).not.toContain('session_risk_score');
    expect(Object.keys((result as any).audit)).not.toContain('correlation_patterns');
  });
});
