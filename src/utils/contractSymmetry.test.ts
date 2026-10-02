/**
 * Cross-language contract-symmetry parity test (MCP responseFormatter).
 *
 * Loads the contract-symmetry fixture vendored under src/__fixtures__/ and
 * asserts that the MCP responseFormatter's sanitized wire responses
 * carry the same governance-outcome fields the SDK sanitizers preserve.
 *
 * MCP wraps the sanitized shape into SanitizedBlockedResponse /
 * SanitizedAllowedResponse / SanitizedApprovalResponse — richer than the
 * SDK ScanResult, but the same top-level governance keys must appear at
 * the same paths (refuse_tier, recovery, session_state.session_locked,
 * content_type).
 *
 * If any language's sanitizer drifts, its parity test fails and CI
 * blocks the merge. The vendored copy is byte-identical to the canonical
 * fixture shared with the SDKs; the last block in this file checks that
 * whenever the canonical copy is reachable.
 */

import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { sanitizeScanResult, sanitizeSQLResult } from './responseFormatter.js';

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

// The vendored copy ships with the package so the suite runs from any checkout.
const FIXTURE_DIR = join(__dirname, '..', '__fixtures__', 'contract-symmetry');
// The canonical copy is shared with the SDKs and is only reachable from the
// monorepo; when present, the vendored copy must match it byte for byte.
const CANONICAL_DIR = join(__dirname, '..', '..', '..', 'testdata', 'contract-symmetry');

function loadFixture<T>(name: string): T {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf-8')) as T;
}

interface CanonicalFixture {
  responses: Record<string, { note?: string; raw: Record<string, any> }>;
}

interface BranchInvariants {
  must_preserve_top_level: string[];
  session_state_must_preserve: string[];
  recovery_must_preserve: string[];
  violation_must_preserve?: string[];
  violation_must_strip?: string[];
  top_level_must_strip: string[];
}

interface Invariants {
  unsafe_branch: BranchInvariants;
  safe_branch: BranchInvariants;
}

const CANONICAL = loadFixture<CanonicalFixture>('canonical-backend-responses.json');
const INVARIANTS = loadFixture<Invariants>('governance-invariants.json');

// ---------------------------------------------------------------------------
// Adapter: map a canonical backend response into MCP's InternalScanResult
// shape so we can feed it through the same sanitizer path the tool runtime
// uses. The MCP tool transformBackendResponse in scan.ts does this at run
// time; here we replicate the essentials to isolate the sanitizer.
// ---------------------------------------------------------------------------

function toInternalScan(raw: Record<string, any>): any {
  const violations = (raw.violations || []).map((v: any) => ({
    threatType: v.threat_type || 'unknown',
    severity: v.severity || 'medium',
    confidence: v.confidence ?? 0.9,
    action: v.action || 'block',
    detectedBy: 'contract-symmetry-fixture',
    message: v.user_message || 'contract-symmetry test violation',
    policyId: v.policy_id || 'pol-fixture',
    policyName: v.policy_name || 'Fixture Policy',
  }));
  return {
    safe: raw.safe !== false,
    threatLevel: raw.threat_level || 'high',
    confidence: 0.9,
    recommendedAction: raw.safe === false ? 'block' : 'allow',
    violations,
    summary: {
      totalViolations: violations.length,
      criticalCount: violations.filter((v: any) => v.severity === 'critical').length,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      blockedCount: violations.length,
      flaggedCount: 0,
    },
    performance: {
      totalScanTimeMs: 10,
      policiesEvaluated: violations.length,
      llmAnalysisUsed: false,
      cacheHits: 0,
    },
    metadata: { scanTimeMs: 10, timedOut: false, scanType: 'full' },
    approvalInfo: raw.approval_info,
    sessionState: raw.session_state ?? undefined,
    refuseTier: raw.refuse_tier,
    recovery: raw.recovery,
    contentType: raw.content_type,
  };
}

function toInternalSpecialized(raw: Record<string, any>): any {
  const issues = raw.threat_type
    ? [{
        type: raw.threat_type,
        severity: 'critical',
        message: raw.threat_type,
      }]
    : [];
  return {
    safe: raw.safe !== false,
    threatLevel: 'high',
    confidence: 0.9,
    recommendedAction: raw.safe === false ? 'block' : 'allow',
    issues,
    metadata: { scanTimeMs: 10 },
    approvalInfo: raw.approval_info,
    sessionState: raw.session_state ?? undefined,
    refuseTier: raw.refuse_tier,
    recovery: raw.recovery,
    contentType: raw.content_type,
  };
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

const REQ_ID = 'req_ci_parity_2026-07-07';
const SESSION_ID = 'ci-parity-2026-07-07';

function eachGeneralCase(): Array<[string, Record<string, any>]> {
  return Object.entries(CANONICAL.responses)
    .filter(([, entry]) => !entry.raw.content_type)
    .map(([name, entry]) => [name, entry.raw]);
}

function eachSpecializedCase(): Array<[string, Record<string, any>]> {
  return Object.entries(CANONICAL.responses)
    .filter(([, entry]) => Boolean(entry.raw.content_type))
    .map(([name, entry]) => [name, entry.raw]);
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

describe('contract-symmetry parity (MCP responseFormatter)', () => {
  it('fixture covers >= 6 canonical cases', () => {
    expect(Object.keys(CANONICAL.responses).length).toBeGreaterThanOrEqual(6);
  });

  it('sanitizeScanResult carries refuse_tier when raw has it', () => {
    for (const [caseName, raw] of eachGeneralCase()) {
      if (raw.refuse_tier === undefined || raw.refuse_tier === null) continue;
      const wire: any = sanitizeScanResult(toInternalScan(raw), REQ_ID, SESSION_ID);
      expect(wire.refuse_tier).toBe(raw.refuse_tier);
    }
  });

  it('sanitizeScanResult carries recovery block when raw has it', () => {
    for (const [caseName, raw] of eachGeneralCase()) {
      if (!raw.recovery) continue;
      const wire: any = sanitizeScanResult(toInternalScan(raw), REQ_ID, SESSION_ID);
      expect(wire.recovery).toBeDefined();
      const branch = raw.safe === false ? INVARIANTS.unsafe_branch : INVARIANTS.safe_branch;
      for (const field of branch.recovery_must_preserve) {
        if (!(field in raw.recovery)) continue;
        expect(wire.recovery[field]).toEqual(raw.recovery[field]);
      }
    }
  });

  it('sanitizeScanResult surfaces session_state.session_locked when raw has it', () => {
    for (const [caseName, raw] of eachGeneralCase()) {
      const ss = raw.session_state;
      if (!ss || ss.session_locked === undefined) continue;
      const wire: any = sanitizeScanResult(toInternalScan(raw), REQ_ID, SESSION_ID);
      expect(wire.session_state).toBeDefined();
      expect(wire.session_state.session_locked).toBe(ss.session_locked);
    }
  });

  it('sanitizeSQLResult surfaces refuse_tier + recovery + content_type on specialized', () => {
    for (const [caseName, raw] of eachSpecializedCase()) {
      const wire: any = sanitizeSQLResult(toInternalSpecialized(raw), REQ_ID, SESSION_ID);
      if (raw.refuse_tier) expect(wire.refuse_tier).toBe(raw.refuse_tier);
      if (raw.recovery) expect(wire.recovery).toBeDefined();
      if (raw.content_type) expect(wire.content_type).toBe(raw.content_type);
      if (raw.session_state?.session_locked !== undefined) {
        expect(wire.session_state?.session_locked).toBe(raw.session_state.session_locked);
      }
    }
  });

  it('action field is preserved on MCP wire (require_approval + block)', () => {
    for (const [caseName, raw] of eachGeneralCase()) {
      const wire: any = sanitizeScanResult(toInternalScan(raw), REQ_ID, SESSION_ID);
      // MCP maps `require_approval` and `block` to `action` directly;
      // `allow` and `warn` map to `action: allow`. Check identity for the
      // action-authoritative cases.
      if (raw.action === 'block') expect(wire.action).toBe('block');
      if (raw.action === 'require_approval') expect(wire.action).toBe('require_approval');
    }
  });
});

// ---------------------------------------------------------------------------
// The vendored fixture must match the canonical copy
// ---------------------------------------------------------------------------

// The copy under src/__fixtures__/ exists so the suite runs from a standalone
// checkout. It is a copy, not a fork: whenever the canonical fixture is
// reachable, every vendored file must match it byte for byte.
const canonicalReachable = existsSync(CANONICAL_DIR);

(canonicalReachable ? describe : describe.skip)('vendored fixture matches the canonical copy', () => {
  const names = readdirSync(FIXTURE_DIR)
    .filter((name) => name.endsWith('.json'))
    .sort();

  it('has at least one vendored file', () => {
    expect(names.length).toBeGreaterThan(0);
  });

  for (const name of names) {
    it(name, () => {
      expect(readFileSync(join(FIXTURE_DIR, name), 'utf-8')).toBe(
        readFileSync(join(CANONICAL_DIR, name), 'utf-8'),
      );
    });
  }
});
