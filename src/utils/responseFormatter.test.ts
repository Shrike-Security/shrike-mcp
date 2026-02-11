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
