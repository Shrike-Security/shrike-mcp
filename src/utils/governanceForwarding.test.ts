/**
 * Contract-symmetry pin tests for the MCP responseFormatter.
 *
 * Verifies that the Cooperative Governance surface
 * — `refuse_tier`, `recovery`, `content_type`, and `session_state.session_locked`
 * — is forwarded from the InternalScanResult through to the sanitized wire
 * response.
 *
 * Pre-2026-07-07 the sanitizer omitted these fields, so callers on the
 * MCP client (Claude Desktop, other MCP hosts) could not see the four-state
 * governance signal. See docs/claude-desktop-e2e-verification-2026-07-07.md
 * — F1 arbiter confirmed backend emits both refuse_tier and recovery.
 */

import { describe, it, expect } from 'vitest';
import {
  sanitizeScanResult,
  sanitizeSQLResult,
  sanitizeFileWriteResult,
  sanitizeCommandResult,
  sanitizeA2AMessageResult,
  sanitizeAgentCardResult,
} from './responseFormatter.js';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SESSION_ID = 'e2e-govforward-2026-07-07';
const REQ_ID = 'req_test_govforward';

const canonicalRecovery = {
  instruction:
    'Rotate session_id and re-verify user intent before retrying. ' +
    'session_status is callable while quarantined.',
  available_tools: ['scan_prompt', 'scan_response', 'session_status'],
  patterns_triggered: ['multi_turn_reconnaissance'],
};

const sessionStateLocked = {
  session_risk_score: 0.9,
  session_turn_number: 5,
  session_patterns: ['multi_turn_reconnaissance'],
  session_locked: true,
};

function blockedScanFixture(): any {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 0.95,
    recommendedAction: 'block',
    violations: [
      {
        threatType: 'prompt_injection',
        severity: 'critical',
        confidence: 0.95,
        action: 'block',
        detectedBy: 'L1_regex',
        message: 'Instruction override pattern detected',
        policyId: 'pol-1',
        policyName: 'Security Policy',
      },
    ],
    summary: {
      totalViolations: 1,
      criticalCount: 1,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      blockedCount: 1,
      flaggedCount: 0,
    },
    performance: {
      totalScanTimeMs: 42,
      policiesEvaluated: 1,
      llmAnalysisUsed: false,
      cacheHits: 0,
    },
    metadata: { scanTimeMs: 42, timedOut: false, scanType: 'full' },
    sessionState: sessionStateLocked,
    refuseTier: 'block' as const,
    recovery: canonicalRecovery,
  };
}

function safeScanFixture(): any {
  return {
    safe: true,
    threatLevel: 'none',
    confidence: 0,
    recommendedAction: 'allow',
    violations: [],
    summary: {
      totalViolations: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      blockedCount: 0,
      flaggedCount: 0,
    },
    performance: {
      totalScanTimeMs: 12,
      policiesEvaluated: 1,
      llmAnalysisUsed: false,
      cacheHits: 0,
    },
    metadata: { scanTimeMs: 12, timedOut: false, scanType: 'full' },
    sessionState: {
      session_risk_score: 0.1,
      session_turn_number: 1,
      session_patterns: [],
    },
    refuseTier: 'allow' as const,
  };
}

function specializedBlockedFixture(contentType: string): any {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 0.9,
    recommendedAction: 'block',
    issues: [
      { type: 'malicious_pattern', severity: 'critical', message: 'blocked' },
    ],
    metadata: { scanTimeMs: 20 },
    sessionState: sessionStateLocked,
    refuseTier: 'block' as const,
    recovery: canonicalRecovery,
    contentType,
  };
}

// ---------------------------------------------------------------------------
// sanitizeScanResult — general observe-plane
// ---------------------------------------------------------------------------

describe('sanitizeScanResult — governance fields forwarded', () => {
  it('block response carries refuse_tier + recovery on the wire', () => {
    const wire = sanitizeScanResult(blockedScanFixture(), REQ_ID, SESSION_ID);
    expect((wire as any).refuse_tier).toBe('block');
    expect((wire as any).recovery).toBeDefined();
    expect((wire as any).recovery.instruction).toMatch(/Rotate session_id/);
    expect((wire as any).recovery.available_tools).toContain('session_status');
  });

  it('block response carries session_state.session_locked=true', () => {
    const wire = sanitizeScanResult(blockedScanFixture(), REQ_ID, SESSION_ID);
    expect(wire.session_state).toBeDefined();
    expect((wire.session_state as any).session_locked).toBe(true);
    expect((wire.session_state as any).session_risk_score).toBe(0.9);
  });

  it('safe response carries refuse_tier=allow (contract symmetry)', () => {
    const wire = sanitizeScanResult(safeScanFixture(), REQ_ID, SESSION_ID);
    expect((wire as any).refuse_tier).toBe('allow');
    expect((wire as any).recovery).toBeUndefined();
  });

  it('omits refuse_tier when backend did not emit (older backends)', () => {
    const fixture = blockedScanFixture();
    delete (fixture as any).refuseTier;
    delete (fixture as any).recovery;
    const wire = sanitizeScanResult(fixture, REQ_ID, SESSION_ID);
    expect((wire as any).refuse_tier).toBeUndefined();
    expect((wire as any).recovery).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Specialized sanitizers — act-plane
// ---------------------------------------------------------------------------

describe.each([
  ['sanitizeSQLResult', sanitizeSQLResult, 'scan_sql_query', 'sql'],
  ['sanitizeFileWriteResult', sanitizeFileWriteResult, 'scan_file_write', 'file_path'],
  ['sanitizeCommandResult', sanitizeCommandResult, 'scan_command', 'command'],
  ['sanitizeA2AMessageResult', sanitizeA2AMessageResult, 'scan_a2a_message', 'a2a_message'],
  ['sanitizeAgentCardResult', sanitizeAgentCardResult, 'scan_agent_card', 'agent_card'],
])('%s — governance fields forwarded', (label, fn, _toolName, contentType) => {
  it('block response carries refuse_tier + recovery + content_type', () => {
    const wire: any = (fn as any)(
      specializedBlockedFixture(contentType),
      REQ_ID,
      SESSION_ID,
    );
    expect(wire.refuse_tier).toBe('block');
    expect(wire.recovery).toBeDefined();
    expect(wire.recovery.instruction).toMatch(/Rotate session_id/);
    expect(wire.content_type).toBe(contentType);
    expect(wire.session_state?.session_locked).toBe(true);
  });
});
