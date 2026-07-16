/**
 * Contract FORWARD-COMPATIBILITY suite (MCP server).
 *
 * Port of the SDK forward-compat suites. Pins the promise that an ADDITIVE
 * backend change (new field, new threat string, new refuse tier) must NOT
 * crash the MCP server or make it fail OPEN — surface a safe/allow verdict
 * on content the backend deemed unsafe.
 *
 * MCP decides blocked/allowed differently from the SDKs: sanitizeScanResult
 * only takes the allow path when `result.safe === true` AND recommendedAction
 * is allow/redact (responseFormatter.ts). Everything else — an unsafe verdict,
 * a missing `safe`, an unrecognized action/tier — falls through to a blocked
 * response. This suite pins that fail-closed-by-construction behavior so a
 * future refactor cannot regress it into a fail-open.
 */

import { describe, it, expect } from 'vitest';
import { sanitizeScanResult } from './responseFormatter.js';

const REQ = 'req_fwdcompat';
const SID = 'sess_fwdcompat';

// Minimal valid InternalScanResult with overridable fields. Typed `any` (as the
// sibling governanceForwarding.test.ts does) to represent wire shapes the
// sanitizer must tolerate.
function scanResult(overrides: Record<string, unknown> = {}): any {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 0.9,
    recommendedAction: 'block',
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
      totalScanTimeMs: 10,
      policiesEvaluated: 1,
      llmAnalysisUsed: false,
      cacheHits: 0,
    },
    metadata: { scanTimeMs: 10, timedOut: false, scanType: 'full' },
    ...overrides,
  };
}

describe('MCP forward-compat: fail CLOSED on anything unrecognized', () => {
  it('blocks an unsafe verdict even when recommendedAction disagrees (allow)', () => {
    // THE CRUX: an unsafe verdict whose action/tier the transform did not map
    // to "block" (e.g. a new backend tier). safe:false must still block —
    // never surface allow just because the action label is unfamiliar.
    const out = sanitizeScanResult(
      scanResult({ safe: false, recommendedAction: 'allow' }),
      REQ,
      SID,
    );
    expect(out.safe).toBe(false);
    expect(out.blocked).toBe(true);
  });

  it('fails closed when `safe` is missing entirely', () => {
    const out = sanitizeScanResult(
      scanResult({ safe: undefined, recommendedAction: 'allow' }),
      REQ,
      SID,
    );
    expect(out.blocked).toBe(true);
  });

  it('forwards an UNKNOWN refuse tier but still blocks the unsafe verdict', () => {
    const out: any = sanitizeScanResult(
      scanResult({ safe: false, recommendedAction: 'block', refuseTier: 'quarantine' }),
      REQ,
      SID,
    );
    expect(out.blocked).toBe(true);
    // The unknown tier is passed through verbatim, not dropped or coerced.
    expect(out.refuse_tier).toBe('quarantine');
  });

  it('still allows a genuinely safe verdict (no spurious blocking)', () => {
    const out = sanitizeScanResult(
      scanResult({ safe: true, recommendedAction: 'allow', threatLevel: 'none' }),
      REQ,
      SID,
    );
    expect(out.safe).toBe(true);
    expect(out.blocked).toBe(false);
  });
});

describe('MCP forward-compat: additive changes do not crash', () => {
  it('tolerates an unknown threat_type in violations without throwing', () => {
    const out = sanitizeScanResult(
      scanResult({
        safe: false,
        recommendedAction: 'block',
        violations: [
          {
            threatType: 'novel_attack_class_v9',
            severity: 'high',
            confidence: 0.9,
            action: 'block',
            detectedBy: 'unknown',
            message: 'new threat',
            policyId: 'p',
            policyName: 'P',
          },
        ],
      }),
      REQ,
      SID,
    );
    expect(out.blocked).toBe(true);
  });

  it('does not throw on a sparse result with an empty violations array', () => {
    expect(() =>
      sanitizeScanResult(scanResult({ violations: [] }), REQ, SID),
    ).not.toThrow();
  });

  it('ignores an unrecognized top-level field', () => {
    expect(() =>
      sanitizeScanResult(
        scanResult({ future_governance_signal: { escalate: true } }),
        REQ,
        SID,
      ),
    ).not.toThrow();
  });
});
