/**
 * Client-side SESSION_ID rotation on high-risk / quarantine, with a
 * three-shape rotation record.
 *
 * The rotation helper `rotateSessionIfTriggered` in config.ts is the single
 * decision point. It emits one of three shapes:
 *
 *   Locked (threat_type === 'session_locked', either ownership):
 *     { rotated: false, rotation_recommended: false, reason: 'session_locked',
 *       current_session_id }
 *     NOTHING rotates and nothing should. The lock is the control; a fresh
 *     session_id sidesteps it rather than clearing it, which is what the
 *     backend's own recovery instruction tells the agent not to do. A lock
 *     lifts by `reset_session` under a live declared scope, or by an
 *     operator. This is the case the suite exists to protect.
 *
 *   Module-owned (score trigger, caller did NOT supply session_id):
 *     { rotated: true, owner: 'mcp_client', previous_session_id, new_session_id }
 *     MCP mutates its module SESSION_ID in place.
 *
 *   Caller-owned (score trigger, caller DID supply session_id):
 *     { rotated: false, rotation_recommended: true, owner: 'caller',
 *       current_session_id, suggested_new_session_id }
 *     MCP does NOT mutate anything — session lifecycle belongs to the caller.
 *
 * These tests pin: the lock path never rotating on either ownership, the
 * score trigger still rotating BELOW the lock, the runtime side effect
 * (module SESSION_ID actually changes for module-owned, does NOT for
 * caller-owned or for a lock), and the sanitizer integration on every path.
 *
 * `SHRIKE_ROTATE_ON_LOCK` is gone. It read as an opt-out and was not one: a
 * locked session is already above the score threshold, so disabling the
 * verdict trigger left the score trigger rotating anyway. `SHRIKE_ROTATION_
 * THRESHOLD` is resolved at module load; verifying it requires a fresh
 * import per case, so the defaults ARE what is tested here.
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

/** A lock notice: nothing rotated, and nothing is being recommended either. */
function asLockNotice(r: any) {
  expect(r).not.toBeNull();
  expect(r.rotated).toBe(false);
  expect(r.rotation_recommended).toBe(false);
  expect(r.reason).toBe('session_locked');
  return r as { rotated: false; rotation_recommended: false; owner: 'mcp_client' | 'caller'; reason: 'session_locked'; current_session_id: string; triggering_risk_score?: number; configured_threshold?: number };
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

  it('does NOT rotate on threat_type === "session_locked"; emits a notice instead', () => {
    const before = getSessionId();
    const r = asLockNotice(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.1),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.owner).toBe('mcp_client');
    expect(r.current_session_id).toBe(before);
    // The whole point: the id the backend locked is the id still in force.
    expect(getSessionId()).toBe(before);
  });

  it('does NOT rotate a locked session even when the score is above threshold', () => {
    // This is the case the old opt-out could not express. The verdict is
    // checked first precisely so the score branch never sees a lock.
    const before = getSessionId();
    const r = asLockNotice(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.95),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.triggering_risk_score).toBe(0.95);
    expect(getSessionId()).toBe(before);
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

  it('the lock wins outright: no rotation, whatever the score says', () => {
    const before = getSessionId();
    const r = asLockNotice(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.95),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    expect(r.reason).toBe('session_locked');
    expect(r.triggering_risk_score).toBe(0.95);
    expect(getSessionId()).toBe(before);
  });
});

describe('rotateSessionIfTriggered (module-owned) — runtime side effect', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('subsequent getSessionId() reflects the rotated ID', () => {
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
    const r = asModuleOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
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

  it('SESSION_ID does NOT change on a lock, however many times it is seen', () => {
    // A locked session that keeps being hit must keep the same id. Rotating
    // here is what used to manufacture the "same agent, N rapid rotations"
    // pattern the correlator reads as an attack signal.
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
    for (let i = 0; i < 3; i++) {
      asLockNotice(rotateSessionIfTriggered({
        threat_type: 'session_locked',
        session_state: state(0.95, i + 1),
        effective_session_id: KNOWN_SESSION_ID,
      }));
      expect(getSessionId()).toBe(KNOWN_SESSION_ID);
    }
  });

  it('two consecutive rotations produce two distinct IDs; second uses the post-first module id', () => {
    const first = asModuleOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
      effective_session_id: KNOWN_SESSION_ID,
    }));
    // After the first rotation, effective_session_id for the next call is the
    // newly-minted module SESSION_ID (that's what a subsequent call without
    // a caller-supplied session_id would send).
    const second = asModuleOwned(rotateSessionIfTriggered({
      session_state: state(0.9),
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
// Regression guard: the caller was passing
// `session_id: "imds-traj"` and the rotation record was reporting UUIDs that
// had nothing to do with the caller's namespace. Under the new contract, the
// caller-owned path echoes back `current_session_id: "imds-traj"` and hands
// out a fresh UUID as a suggestion, without mutating anything MCP owns.
// ---------------------------------------------------------------------------

describe('rotateSessionIfTriggered (caller-owned) — verdict-based (session_locked)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('emits a lock notice on session_locked, and suggests nothing', () => {
    const beforeModuleId = getSessionId();
    const notice = asLockNotice(rotateSessionIfTriggered({
      threat_type: 'session_locked',
      session_state: state(0.9),
      effective_session_id: CALLER_SESSION_ID,
    }));
    expect(notice.owner).toBe('caller');
    expect(notice.current_session_id).toBe(CALLER_SESSION_ID);
    // No suggested_new_session_id on this shape: suggesting a fresh id is
    // suggesting the caller sidestep the lock. The notice exists so the
    // agent LEARNS the session locked, not so it can route around it.
    expect((notice as any).suggested_new_session_id).toBeUndefined();
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

  it('sanitizeScanResult blocked response with session_locked emits a notice, not a rotation', () => {
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
    const notice = asLockNotice((result as any).client_session_rotation);
    expect(notice.owner).toBe('mcp_client');
    expect(notice.current_session_id).toBe(KNOWN_SESSION_ID);
    // The session the backend locked is the session still in force. A scan
    // that quarantines must not hand the agent a clean id on the way out.
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
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

  it('act-plane sanitizeCommandResult also refuses to rotate on session_locked', () => {
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
    const notice = asLockNotice((result as any).client_session_rotation);
    expect(notice.owner).toBe('mcp_client');
    expect(getSessionId()).toBe(KNOWN_SESSION_ID);
  });
});

describe('sanitized response carries client_session_rotation (caller-owned)', () => {
  beforeEach(() => __resetSessionIdForTesting(KNOWN_SESSION_ID));

  it('sanitizeScanResult with caller-supplied session_id emits a lock notice, not a recommendation', () => {
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
    const notice = asLockNotice((result as any).client_session_rotation);
    expect(notice.owner).toBe('caller');
    // Namespace correctness: `current_session_id` is what the caller
    // supplied, not a UUID they have never seen.
    expect(notice.current_session_id).toBe(CALLER_SESSION_ID);
    // And nothing is suggested. A caller who owns the session still must
    // not be told that minting a new id is the way past a lock.
    expect(notice.suggested_new_session_id).toBeUndefined();
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
