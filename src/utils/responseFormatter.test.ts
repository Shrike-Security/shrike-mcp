/**
 * Unit tests for responseFormatter
 * Verifies IP protection through response sanitization
 */

import { describe, it, expect } from 'vitest';
import {
  generateRequestId,
  bucketConfidence,
  normalizeThreatType,
  getGuidance,
  getHighestSeverity,
  sanitizeScanResult,
  sanitizeSQLResult,
  sanitizeFileWriteResult,
  sanitizeWebSearchResult,
} from './responseFormatter.js';

describe('responseFormatter', () => {
  describe('generateRequestId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateRequestId();
      const id2 = generateRequestId();
      expect(id1).not.toEqual(id2);
    });

    it('should have correct format with req_ prefix', () => {
      const id = generateRequestId();
      expect(id).toMatch(/^req_[a-z0-9]+_[a-z0-9]+$/);
    });

    it('should generate IDs of consistent length', () => {
      const ids = Array.from({ length: 10 }, () => generateRequestId());
      ids.forEach((id) => {
        expect(id.length).toBeGreaterThan(10);
        expect(id.length).toBeLessThan(30);
      });
    });
  });

  describe('bucketConfidence', () => {
    it('should return "high" for >= 0.9', () => {
      expect(bucketConfidence(0.9)).toBe('high');
      expect(bucketConfidence(0.95)).toBe('high');
      expect(bucketConfidence(1.0)).toBe('high');
    });

    it('should return "medium" for >= 0.7 and < 0.9', () => {
      expect(bucketConfidence(0.7)).toBe('medium');
      expect(bucketConfidence(0.85)).toBe('medium');
      expect(bucketConfidence(0.89)).toBe('medium');
    });

    it('should return "low" for < 0.7', () => {
      expect(bucketConfidence(0.5)).toBe('low');
      expect(bucketConfidence(0.69)).toBe('low');
      expect(bucketConfidence(0)).toBe('low');
    });
  });

  describe('normalizeThreatType', () => {
    it('should map known threat types', () => {
      expect(normalizeThreatType('prompt_injection')).toBe('prompt_injection');
      expect(normalizeThreatType('sql_injection')).toBe('sql_injection');
      expect(normalizeThreatType('path_traversal')).toBe('path_traversal');
      expect(normalizeThreatType('jailbreak')).toBe('jailbreak');
    });

    it('should normalize variants to standard types', () => {
      expect(normalizeThreatType('pii')).toBe('pii_exposure');
      expect(normalizeThreatType('secrets')).toBe('secrets_exposure');
      expect(normalizeThreatType('sqli')).toBe('sql_injection');
    });

    it('should return "unknown" for unmapped types', () => {
      expect(normalizeThreatType('some_new_type')).toBe('unknown');
      expect(normalizeThreatType('')).toBe('unknown');
    });

    it('should be case-insensitive', () => {
      expect(normalizeThreatType('PROMPT_INJECTION')).toBe('prompt_injection');
      expect(normalizeThreatType('Jailbreak')).toBe('jailbreak');
    });
  });

  describe('getGuidance', () => {
    it('should return guidance for all threat types', () => {
      const threatTypes = [
        'prompt_injection',
        'jailbreak',
        'data_exfiltration',
        'sql_injection',
        'path_traversal',
        'secrets_exposure',
        'pii_exposure',
        'blocked_domain',
        'scan_error',
        'unknown',
      ] as const;

      threatTypes.forEach((type) => {
        const guidance = getGuidance(type);
        expect(guidance).toBeTruthy();
        expect(guidance.length).toBeGreaterThan(20);
      });
    });

    it('should not expose detection methods in guidance', () => {
      const guidance = getGuidance('prompt_injection');
      expect(guidance.toLowerCase()).not.toContain('regex');
      expect(guidance.toLowerCase()).not.toContain('llm');
      expect(guidance.toLowerCase()).not.toContain('layer');
      expect(guidance.toLowerCase()).not.toContain('l6');
    });
  });

  describe('getHighestSeverity', () => {
    it('should return critical as highest', () => {
      expect(getHighestSeverity(['low', 'medium', 'critical', 'high'])).toBe('critical');
    });

    it('should return high when no critical', () => {
      expect(getHighestSeverity(['low', 'high', 'medium'])).toBe('high');
    });

    it('should return medium as default', () => {
      expect(getHighestSeverity([])).toBe('medium');
      expect(getHighestSeverity(['unknown'])).toBe('medium');
    });
  });

  // =========================================================================
  // APPROVAL RESPONSE TESTS (require_approval action)
  // =========================================================================

  describe('approval responses', () => {
    const requestId = 'req_approval_test';

    const approvalInfo = {
      requires_approval: true,
      approval_id: 'appr-uuid-123',
      approval_level: 'edge',
      action_summary: 'DELETE FROM production.users WHERE id = 42',
      policy_name: 'Production DELETE Policy',
      expires_in_seconds: 1800,
    };

    describe('sanitizeScanResult with approvalInfo', () => {
      it('should return require_approval when safe scan has approvalInfo', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          violations: [],
          performance: {
            totalScanTimeMs: 100,
            policiesEvaluated: 10,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
          approvalInfo,
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('require_approval');
        if (sanitized.action === 'require_approval') {
          expect(sanitized.approval_id).toBe('appr-uuid-123');
          expect(sanitized.approval_context.policy_name).toBe('Production DELETE Policy');
          expect(sanitized.approval_context.approval_level).toBe('edge');
          expect(sanitized.approval_context.action_summary).toContain('DELETE FROM');
          expect(sanitized.approval_context.expires_in_seconds).toBe(1800);
          expect(sanitized.agent_instruction).toContain('HOLD');
          expect(sanitized.agent_instruction).toContain('Do NOT proceed');
          expect(sanitized.user_message).toContain('appr-uuid-123');
          expect(sanitized.user_message).toContain('30 minutes');
          expect(sanitized.audit.scan_id).toBe(requestId);
          expect(sanitized.audit.policy_name).toBe('Production DELETE Policy');
          expect(sanitized.request_id).toBe(requestId);
        }
      });

      it('should NOT return approval when safe=false (blocked wins)', () => {
        const internalResult = {
          safe: false,
          threatLevel: 'high',
          confidence: 0.95,
          recommendedAction: 'block' as const,
          violations: [
            {
              threatType: 'sql_injection',
              severity: 'high',
              confidence: 0.95,
              action: 'block',
              detectedBy: 'regex',
              message: 'Test',
              policyId: 'pol-1',
              policyName: 'Test',
            },
          ],
          performance: {
            totalScanTimeMs: 100,
            policiesEvaluated: 10,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
          approvalInfo, // present but should be ignored because safe=false
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('block'); // block, not require_approval
      });

      it('should return allow when safe with no approvalInfo', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          violations: [],
          performance: {
            totalScanTimeMs: 50,
            policiesEvaluated: 5,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(false);
        expect(sanitized.action).toBe('allow');
      });

      it('should return allow when approvalInfo.requires_approval is false', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          violations: [],
          performance: {
            totalScanTimeMs: 50,
            policiesEvaluated: 5,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
          approvalInfo: { ...approvalInfo, requires_approval: false },
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(false);
        expect(sanitized.action).toBe('allow');
      });
    });

    describe('sanitizeSQLResult with approvalInfo', () => {
      it('should return require_approval for safe SQL with approvalInfo', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          issues: [],
          metadata: { scanTimeMs: 30, queryLength: 50, statementType: 'DELETE' },
          approvalInfo,
        };

        const sanitized = sanitizeSQLResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('require_approval');
        if (sanitized.action === 'require_approval') {
          expect(sanitized.approval_id).toBe('appr-uuid-123');
          expect(sanitized.approval_context.expires_in_seconds).toBe(1800);
        }
      });
    });

    describe('sanitizeFileWriteResult with approvalInfo', () => {
      it('should return require_approval for safe file write with approvalInfo', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          issues: [],
          metadata: { scanTimeMs: 20, pathLength: 30, contentLength: 100, fileExtension: 'conf' },
          approvalInfo,
        };

        const sanitized = sanitizeFileWriteResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('require_approval');
        if (sanitized.action === 'require_approval') {
          expect(sanitized.approval_id).toBe('appr-uuid-123');
          expect(sanitized.user_message).toContain('approval');
        }
      });
    });

    describe('sanitizeWebSearchResult with approvalInfo', () => {
      it('should return require_approval for safe web search with approvalInfo', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          issues: [],
          metadata: { scanTimeMs: 15, queryLength: 25, domainsChecked: 0 },
          approvalInfo,
        };

        const sanitized = sanitizeWebSearchResult(internalResult, requestId);

        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('require_approval');
        if (sanitized.action === 'require_approval') {
          expect(sanitized.approval_id).toBe('appr-uuid-123');
          expect(sanitized.approval_context.policy_name).toBe('Production DELETE Policy');
        }
      });
    });

    describe('approval response structure', () => {
      it('should compute expires_in minutes correctly', () => {
        const shortExpiry = {
          ...approvalInfo,
          expires_in_seconds: 90, // 1.5 minutes → ceil to 2
        };
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          violations: [],
          performance: {
            totalScanTimeMs: 50,
            policiesEvaluated: 5,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
          approvalInfo: shortExpiry,
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        if (sanitized.action === 'require_approval') {
          expect(sanitized.user_message).toContain('2 minutes');
        }
      });

      it('should include audit block with policy_name', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          violations: [],
          performance: {
            totalScanTimeMs: 50,
            policiesEvaluated: 5,
            llmAnalysisUsed: false,
            cacheHits: 0,
          },
          approvalInfo,
        };

        const sanitized = sanitizeScanResult(internalResult, requestId);

        expect(sanitized.audit).toBeDefined();
        expect(sanitized.audit.scan_id).toBe(requestId);
        expect(sanitized.audit.timestamp).toBeDefined();
        if (sanitized.action === 'require_approval') {
          expect(sanitized.audit.policy_name).toBe('Production DELETE Policy');
        }
      });

      it('should have blocked=true to halt agents that only check blocked', () => {
        const internalResult = {
          safe: true,
          threatLevel: 'none',
          confidence: 0,
          recommendedAction: 'allow' as const,
          issues: [],
          metadata: { scanTimeMs: 10, queryLength: 20, statementType: 'DELETE' },
          approvalInfo,
        };

        const sanitized = sanitizeSQLResult(internalResult, requestId);

        // This is critical: blocked=true ensures agents halt even if they don't
        // understand require_approval action
        expect(sanitized.blocked).toBe(true);
        expect(sanitized.action).toBe('require_approval');
      });
    });
  });

  // =========================================================================
  // EXISTING TESTS
  // =========================================================================

  describe('sanitizeScanResult', () => {
    const requestId = 'req_test123';

    it('should return blocked=false for safe results', () => {
      const internalResult = {
        safe: true,
        threatLevel: 'none',
        confidence: 0,
        recommendedAction: 'allow' as const,
        violations: [],
        performance: {
          totalScanTimeMs: 100,
          policiesEvaluated: 10,
          llmAnalysisUsed: false,
          cacheHits: 0,
        },
      };

      const sanitized = sanitizeScanResult(internalResult, requestId);

      expect(sanitized.blocked).toBe(false);
      expect(sanitized.request_id).toBe(requestId);
      expect('threat_type' in sanitized).toBe(false);
      expect('guidance' in sanitized).toBe(false);
    });

    it('should remove internal fields for blocked results', () => {
      const internalResult = {
        safe: false,
        threatLevel: 'high',
        confidence: 0.95,
        recommendedAction: 'block' as const,
        violations: [
          {
            threatType: 'prompt_injection',
            severity: 'high',
            confidence: 0.95,
            action: 'block',
            detectedBy: 'regex', // Internal field
            message: 'Test',
            policyId: 'pol-123', // Internal field
            policyName: 'Test Policy',
            matchedPattern: 'ignore previous', // Internal field
          },
        ],
        llmAnalysis: {
          analyzed: true,
          isMalicious: true,
          confidence: 0.95,
          threatType: 'prompt_injection',
          reasoning: 'Test reasoning', // Internal field
          detectedBy: 'llm_only', // Internal field
          analysisTimeMs: 500,
        },
        performance: {
          totalScanTimeMs: 100,
          policiesEvaluated: 10,
          llmAnalysisUsed: true,
          cacheHits: 0,
        },
      };

      const sanitized = sanitizeScanResult(internalResult, requestId);

      // Should have obfuscated fields
      expect(sanitized.blocked).toBe(true);
      expect(sanitized.request_id).toBe(requestId);

      if (sanitized.blocked) {
        expect(sanitized.threat_type).toBe('prompt_injection');
        expect(sanitized.confidence).toBe('high'); // Bucketed
        expect(sanitized.guidance).toContain('instruction override');

        // Should NOT have internal fields
        expect('detectedBy' in sanitized).toBe(false);
        expect('policyId' in sanitized).toBe(false);
        expect('matchedPattern' in sanitized).toBe(false);
        expect('llmAnalysis' in sanitized).toBe(false);
        expect('violations' in sanitized).toBe(false);
        expect('performance' in sanitized).toBe(false);
      }
    });

    it('should bucket confidence correctly', () => {
      const createResult = (confidence: number) => ({
        safe: false,
        threatLevel: 'high',
        confidence,
        recommendedAction: 'block' as const,
        violations: [
          {
            threatType: 'prompt_injection',
            severity: 'high',
            confidence,
            action: 'block',
            detectedBy: 'regex',
            message: 'Test',
            policyId: 'pol-123',
            policyName: 'Test',
          },
        ],
        performance: {
          totalScanTimeMs: 100,
          policiesEvaluated: 10,
          llmAnalysisUsed: false,
          cacheHits: 0,
        },
      });

      const highResult = sanitizeScanResult(createResult(0.95), requestId);
      const mediumResult = sanitizeScanResult(createResult(0.75), requestId);
      const lowResult = sanitizeScanResult(createResult(0.5), requestId);

      if (highResult.blocked && mediumResult.blocked && lowResult.blocked) {
        expect(highResult.confidence).toBe('high');
        expect(mediumResult.confidence).toBe('medium');
        expect(lowResult.confidence).toBe('low');
      }
    });
  });

  describe('sanitizeSQLResult', () => {
    const requestId = 'req_sql_test';

    it('should sanitize SQL results correctly', () => {
      const internalResult = {
        safe: false,
        threatLevel: 'critical',
        confidence: 0.98,
        recommendedAction: 'block' as const,
        issues: [
          {
            type: 'sql_injection',
            severity: 'critical',
            message: 'UNION attack detected',
            pattern: "' UNION SELECT", // Should be removed
          },
        ],
        metadata: {
          scanTimeMs: 50,
          queryLength: 100,
          statementType: 'SELECT',
        },
      };

      const sanitized = sanitizeSQLResult(internalResult, requestId);

      expect(sanitized.blocked).toBe(true);
      expect(sanitized.request_id).toBe(requestId);

      if (sanitized.blocked) {
        expect(sanitized.threat_type).toBe('sql_injection');
        expect(sanitized.confidence).toBe('high');
        expect(sanitized.guidance).toContain('SQL patterns');

        // Should NOT have internal fields
        expect('issues' in sanitized).toBe(false);
        expect('metadata' in sanitized).toBe(false);
        expect('pattern' in sanitized).toBe(false);
      }
    });
  });

  describe('sanitizeFileWriteResult', () => {
    const requestId = 'req_file_test';

    it('should sanitize file write results correctly', () => {
      const internalResult = {
        safe: false,
        threatLevel: 'high',
        confidence: 0.9,
        recommendedAction: 'block' as const,
        issues: [
          {
            type: 'path_traversal',
            severity: 'high',
            message: 'Path traversal detected',
            location: 'path' as const,
          },
        ],
        metadata: {
          scanTimeMs: 30,
          pathLength: 50,
          contentLength: 1000,
          fileExtension: 'txt',
        },
      };

      const sanitized = sanitizeFileWriteResult(internalResult, requestId);

      expect(sanitized.blocked).toBe(true);
      if (sanitized.blocked) {
        expect(sanitized.threat_type).toBe('path_traversal');
        expect(sanitized.guidance).toContain('directories outside');
      }
    });
  });

  describe('sanitizeWebSearchResult', () => {
    const requestId = 'req_web_test';

    it('should sanitize web search results correctly', () => {
      const internalResult = {
        safe: false,
        threatLevel: 'high',
        confidence: 0.85,
        recommendedAction: 'block' as const,
        issues: [
          {
            type: 'blocked_domain',
            severity: 'high',
            message: 'Blocked domain',
            pattern: 'pastebin.com', // Should be removed
          },
        ],
        metadata: {
          scanTimeMs: 40,
          queryLength: 30,
          domainsChecked: 1,
        },
      };

      const sanitized = sanitizeWebSearchResult(internalResult, requestId);

      expect(sanitized.blocked).toBe(true);
      if (sanitized.blocked) {
        expect(sanitized.threat_type).toBe('blocked_domain');
        expect(sanitized.guidance).toContain('restricted domain');
      }
    });
  });
});
