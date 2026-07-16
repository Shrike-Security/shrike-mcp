/**
 * Client-side SESSION_ID rotation on high-risk / quarantine, with a
 * two-shape rotation record.
 *
 * The rotation helper `rotateSessionIfTriggered` in config.ts is the single
 * decision point. It emits one of two shapes based on session ownership:
 *
 *   Module-owned (caller did NOT supply session_id, MCP fallback in use):
 *     { rotated: true, owner: 'mcp_client', previous_session_id, new_session_id }
 *     MCP mutates its module SESSION_ID in place.
 *
 *   Caller-owned (caller DID supply session_id on the tool call):
 *     { rotated: false, rotation_recommended: true, owner: 'caller',
 *       current_session_id, suggested_new_session_id }
 *     MCP does NOT mutate anything — session lifecycle belongs to the caller.
 *
 * These tests pin: the two triggers (verdict-based `session_locked` and
 * score-based `SessionState.session_risk_score >= threshold`), the ordering
 * when both fire, the runtime side effect (module SESSION_ID actually
 * changes for module-owned, does NOT for caller-owned), and the sanitizer
 * integration on both ownership paths.
 *
 * Env-var overrides (`SHRIKE_ROTATE_ON_LOCK`, `SHRIKE_ROTATION_THRESHOLD`)
 * are resolved at module load; verifying them requires a fresh import per
 * case. Not exercised here — the defaults ARE what's tested, and a
 * follow-up integration test in a fresh process is the right shape for
 * env-driven overrides.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  rotateSessionIfTriggered,
  getSessionId,
  __resetSessionIdForTesting,
} from '../config.js';
import {
  sanitizeScanResult,
  sanitizeCommandResult,
} from './responseFormatter.js';

const RISK_THRESHOLD_DEFAULT = 0.7;

const KNOWN_SESSION_ID = '00000000-0000-0000-0000-000000000000';
const CALLER_SESSION_ID = 'imds-traj';

function state(risk: number, turn = 1, patterns: string[] = []) {
  return { session_risk_score: risk, session_turn_number: turn, session_patterns: patterns };
}

// Type-narrowing helpers — the rotation record is a discriminated union.
function asModuleOwned(r: any) {
  expect(r).not.toBeNull();
  expect(r.rotated).toBe(true);
  expect(r.owner).toBe('mcp_client');
  return r as { rotated: true; owner: 'mcp_client'; reason: string; previous_session_id: string; new_session_id: string; triggering_risk_score?: number; configured_threshold?: number };
}

function asCallerOwned(r: any) {
  expect(r).not.toBeNull();
  expect(r.rotated).toBe(false);
  expect(r.rotation_recommended).toBe(true);
  expect(r.owner).toBe('caller');
  return r as { rotated: false; rotation_recommended: true; owner: 'caller'; reason: string; current_session_id: string; suggested_new_session_id: string; triggering_risk_score?: number; configured_threshold?: number };
}

// ---------------------------------------------------------------------------
// Module-owned rotation — caller did NOT supply session_id, MCP fallback used.
// effective_session_id === current module SESSION_ID → ownership is mcp_client.
// ---------------------------------------------------------------------------

describe('rotateSessionIfTriggered (module-owned) — verdict-based (session_locked)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('rotates on threat_type === "session_locked" regardless of session_state score', () => {
    const before = getSessionId();
    const r = asModuleOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.1),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.reason).toBe('session_locked');
    expect(r.previous_session_id).toBe(before);
    expect(r.new_session_id).not.toBe(before);
    expect(getSessionId()).toBe(r.new_session_id);
  });

  it('does NOT rotate on unrelated threat_type', () => {
    const before = getSessionId();
    const rotation = rotateSessionIfTriggered({
      threat_type: 'prompt_injection',
      session_state: state(0.1),
      effective_session_id: KNOWN_SESSION_ID,
    });
    expect(rotation).toBeNull();
    expect(getSessionId()).toBe(before);
  });

  it('does NOT rotate when threat_type is undefined and score is below threshold', () => {
    const before = getSessionId();
    const rotation = rotateSessionIfTriggered({
      session_state: state(0.3),
      effective_session_id: KNOWN_SESSION_ID,
    });
    expect(rotation).toBeNull();
    expect(getSessionId()).toBe(before);
  });
});

describe('rotateSessionIfTriggered (module-owned) — score-based (risk >= threshold)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('rotates when session_risk_score is exactly at threshold', () => {
    const r = asModuleOwned(rotateSessionIfTriggered({
      session_state: state(RISK_THRESHOLD_DEFAULT),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.reason).toBe('risk_threshold_exceeded');
    expect(r.triggering_risk_score).toBe(RISK_THRESHOLD_DEFAULT);
    expect(r.configured_threshold).toBe(RISK_THRESHOLD_DEFAULT);
  });

  it('rotates when session_risk_score is above threshold', () => {
    const r = asModuleOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.reason).toBe('risk_threshold_exceeded');
    expect(r.triggering_risk_score).toBe(0.9);
  });

  it('does NOT rotate when score is just below threshold', () => {
    const before = getSessionId();
    const rotation = rotateSessionIfTriggered({
      session_state: state(RISK_THRESHOLD_DEFAULT - 0.01),
      effective_session_id: KNOWN_SESSION_ID,
    });
    expect(rotation).toBeNull();
    expect(getSessionId()).toBe(before);
  });

  it('does NOT rotate when session_state is absent (no state = no threshold check)', () => {
    const before = getSessionId();
    const rotation = rotateSessionIfTriggered({ effective_session_id: KNOWN_SESSION_ID });
    expect(rotation).toBeNull();
    expect(getSessionId()).toBe(before);
  });
});

describe('rotateSessionIfTriggered (module-owned) — precedence when both fire', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('verdict wins the reason label when session_locked AND score above threshold', () => {
    const r = asModuleOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.95),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.reason).toBe('session_locked'); // verdict is more specific
    expect(r.triggering_risk_score).toBe(0.95);
  });
});

describe('rotateSessionIfTriggered (module-owned) — runtime side effect', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('subsequent getSessionId() reflects the rotated ID', () => {
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
    const r = asModuleOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(getSessionId()).toBe(r.new_session_id);
    expect(getSessionId()).not.toBe(KNOWN_SESSION_ID);
  });

  it('SESSION_ID does NOT change when no trigger fired', () => {
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
    rotateSessionIfTriggered({ session_state: state(0.2), effective_session_id: KNOWN_SESSION_ID });
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
  });

  it('two consecutive rotations produce two distinct IDs; second uses the post-first module id', () => {
    const first = asModuleOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      effective_session_id: KNOWN_SESSION_ID,
    }));
    // After the first rotation, effective_session_id for the next call is the
    // newly-minted module SESSION_ID (that's what a subsequent call without
    // a caller-supplied session_id would send).
    const second = asModuleOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      effective_session_id: first.new_session_id,
    }));
    expect(first.new_session_id).not.toBe(second.new_session_id);
    expect(second.previous_session_id).toBe(first.new_session_id);
  });
});

// ---------------------------------------------------------------------------
// Caller-owned rotation recommendation — caller supplied session_id on the
// tool call. effective_session_id !== current module SESSION_ID → ownership
// is caller. MCP does NOT mutate its module SESSION_ID; it emits a
// recommendation and lets the caller decide.
//
// This is the §4 fix from the 2026-07-06 smoke test — the caller was passing
// `session_id: "imds-traj"` and the rotation record was reporting UUIDs that
// had nothing to do with the caller's namespace. Under the new contract, the
// caller-owned path echoes back `current_session_id: "imds-traj"` and hands
// out a fresh UUID as a suggestion, without mutating anything MCP owns.
// ---------------------------------------------------------------------------

describe('rotateSessionIfTriggered (caller-owned) — verdict-based (session_locked)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('emits recommendation on session_locked; does NOT mutate module SESSION_ID', () => {
    const beforeModuleId = getSessionId();
    const rec = asCallerOwned(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.9),
      effective_session_id: CALLER_SESSION_ID,
    }));
    expect(rec.reason).toBe('session_locked');
    expect(rec.current_session_id).toBe(CALLER_SESSION_ID);
    expect(rec.suggested_new_session_id).not.toBe(CALLER_SESSION_ID);
    expect(rec.suggested_new_session_id).not.toBe(beforeModuleId);
    // The critical invariant: MCP does NOT mutate its own SESSION_ID when
    // the caller owns the session — because that mutation would be a no-op
    // for the caller (who keeps using their own id) AND misleading (previous
    // vs new UUIDs the caller never sees).
    expect(getSessionId()).toBe(beforeModuleId);
  });

  it('does NOT emit on unrelated threat_type', () => {
    const rotation = rotateSessionIfTriggered({
      threat_type: 'prompt_injection',
      session_state: state(0.1),
      effective_session_id: CALLER_SESSION_ID,
    });
    expect(rotation).toBeNull();
  });
});

describe('rotateSessionIfTriggered (caller-owned) — score-based', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('emits recommendation when risk score crosses threshold', () => {
    const beforeModuleId = getSessionId();
    const rec = asCallerOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
      effective_session_id: CALLER_SESSION_ID,
    }));
    expect(rec.reason).toBe('risk_threshold_exceeded');
    expect(rec.current_session_id).toBe(CALLER_SESSION_ID);
    expect(rec.triggering_risk_score).toBe(0.9);
    expect(rec.configured_threshold).toBe(RISK_THRESHOLD_DEFAULT);
    expect(getSessionId()).toBe(beforeModuleId); // unchanged
  });

  it('two consecutive recommendations do NOT drift the module SESSION_ID', () => {
    const before = getSessionId();
    rotateSessionIfTriggered({
      session_state: state(0.9),
      effective_session_id: CALLER_SESSION_ID,
    });
    rotateSessionIfTriggered({
      session_state: state(0.95),
      effective_session_id: CALLER_SESSION_ID,
    });
    expect(getSessionId()).toBe(before);
  });

  it('each recommendation yields a fresh suggested_new_session_id', () => {
    const first = asCallerOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
      effective_session_id: CALLER_SESSION_ID,
    }));
    const second = asCallerOwned(rotateSessionIfTriggered({
      session_state: state(0.95),
      effective_session_id: CALLER_SESSION_ID,
    }));
    expect(first.suggested_new_session_id).not.toBe(second.suggested_new_session_id);
  });
});

// ---------------------------------------------------------------------------
// Integration — sanitizer surfaces client_session_rotation top-level when
// the response would have triggered a rotation. Verifies the wire contract
// customers actually see, on both ownership paths.
// ---------------------------------------------------------------------------

describe('sanitized response carries client_session_rotation (module-owned)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('sanitizeScanResult blocked response with session_locked triggers module-owned rotation', () => {
    const result = sanitizeScanResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block',
        violations: [{
          threatType: 'session_locked', severity: 'high', confidence: 0.9,
          action: 'block', policyId: 'p1', policyName: 'Session Quarantine',
          detectedBy: 'L9', message: 'session quarantined',
        }],
        summary: { totalViolations: 1, criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, blockedCount: 1 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: { session_risk_score: 0.9, session_turn_number: 5, session_patterns: ['multi_turn_escalation'] },
      } as any,
      'req-locked-1',
      KNOWN_SESSION_ID, // effective_session_id — module fallback in use
      'scan_prompt',
    );
    const rotation = (result as any).client_session_rotation;
    expect(rotation).toBeDefined();
    expect(rotation.rotated).toBe(true);
    expect(rotation.owner).toBe('mcp_client');
    expect(rotation.reason).toBe('session_locked');
    expect(rotation.previous_session_id).toBe(KNOWN_SESSION_ID);
    expect(rotation.new_session_id).not.toBe(KNOWN_SESSION_ID);
    expect((result as any).session_state.session_risk_score).toBe(0.9);
  });

  it('sanitizeScanResult allowed response with high risk score triggers module-owned rotation', () => {
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
        sessionState: { session_risk_score: 0.75, session_turn_number: 4, session_patterns: [] },
      } as any,
      'req-highrisk-1',
      KNOWN_SESSION_ID,
      'scan_prompt',
    );
    const rotation = (result as any).client_session_rotation;
    expect(rotation).toBeDefined();
    expect(rotation.rotated).toBe(true);
    expect(rotation.owner).toBe('mcp_client');
    expect(rotation.reason).toBe('risk_threshold_exceeded');
    expect(rotation.triggering_risk_score).toBe(0.75);
  });

  it('sanitizeScanResult allowed response with low risk does NOT emit rotation', () => {
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
        sessionState: { session_risk_score: 0.3, session_turn_number: 1, session_patterns: [] },
      } as any,
      'req-lowrisk-1',
      KNOWN_SESSION_ID,
      'scan_prompt',
    );
    expect((result as any).client_session_rotation).toBeUndefined();
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
  });

  it('act-plane sanitizeCommandResult also emits module-owned rotation on session_locked', () => {
    const result = sanitizeCommandResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block',
        issues: [{ type: 'session_locked', severity: 'high', message: 'session quarantined' }],
        metadata: { scanTimeMs: 1 },
        sessionState: { session_risk_score: 0.9, session_turn_number: 5, session_patterns: [] },
      } as any,
      'req-cmd-locked',
      KNOWN_SESSION_ID,
      'scan_command',
    );
    const rotation = (result as any).client_session_rotation;
    expect(rotation).toBeDefined();
    expect(rotation.rotated).toBe(true);
    expect(rotation.owner).toBe('mcp_client');
    expect(rotation.reason).toBe('session_locked');
  });
});

describe('sanitized response carries client_session_rotation (caller-owned)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('sanitizeScanResult with caller-supplied session_id emits recommendation, not mutation', () => {
    const beforeModuleId = getSessionId();
    const result = sanitizeScanResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block',
        violations: [{
          threatType: 'session_locked', severity: 'high', confidence: 0.9,
          action: 'block', policyId: 'p1', policyName: 'Session Quarantine',
          detectedBy: 'L9', message: 'session quarantined',
        }],
        summary: { totalViolations: 1, criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, blockedCount: 1 },
        performance: { totalScanTimeMs: 1, policiesEvaluated: 0, llmAnalysisUsed: false, cacheHits: 0 },
        metadata: { scanTimeMs: 1, timedOut: false, scanType: 'full' },
        sessionState: { session_risk_score: 0.9, session_turn_number: 5, session_patterns: ['multi_turn_escalation'] },
      } as any,
      'req-caller-locked',
      CALLER_SESSION_ID,
      'scan_prompt',
    );
    const rec = (result as any).client_session_rotation;
    expect(rec).toBeDefined();
    // Discriminant fields for the caller-owned branch
    expect(rec.rotated).toBe(false);
    expect(rec.rotation_recommended).toBe(true);
    expect(rec.owner).toBe('caller');
    expect(rec.reason).toBe('session_locked');
    // Namespace correctness — the whole point of the fix. `current_session_id`
    // is what the caller supplied, not a UUID they've never seen.
    expect(rec.current_session_id).toBe(CALLER_SESSION_ID);
    expect(rec.suggested_new_session_id).not.toBe(CALLER_SESSION_ID);
    // Module SESSION_ID unchanged — MCP did not mutate anything.
    expect(getSessionId()).toBe(beforeModuleId);
  });

  it('sanitizeCommandResult with caller-supplied session_id emits recommendation on high risk', () => {
    const beforeModuleId = getSessionId();
    const result = sanitizeCommandResult(
      {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block',
        issues: [{ type: 'destructive_operation', severity: 'high', message: 'rm -rf' }],
        metadata: { scanTimeMs: 1 },
        sessionState: { session_risk_score: 0.85, session_turn_number: 4, session_patterns: ['multi_turn_reconnaissance'] },
      } as any,
      'req-cmd-caller-highrisk',
      CALLER_SESSION_ID,
      'scan_command',
    );
    const rec = (result as any).client_session_rotation;
    expect(rec).toBeDefined();
    expect(rec.rotated).toBe(false);
    expect(rec.rotation_recommended).toBe(true);
    expect(rec.owner).toBe('caller');
    expect(rec.reason).toBe('risk_threshold_exceeded');
    expect(rec.current_session_id).toBe(CALLER_SESSION_ID);
    expect(rec.triggering_risk_score).toBe(0.85);
    expect(getSessionId()).toBe(beforeModuleId);
  });
});
