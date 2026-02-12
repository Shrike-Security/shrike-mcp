/**
 * scan_response Tool
 * Scans LLM-generated responses for security threats before showing to users.
 *
 * Detects:
 * - System prompt leaks (LLM revealing its instructions)
 * - Unexpected PII in output (PII not present in original prompt)
 * - Toxic/hostile language
 * - Topic drift (response diverges from prompt intent)
 * - Policy violations in generated content
 *
 * Requires both the original prompt and the LLM response for full analysis.
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeScanResult,
  logInternalDetails,
  extractScanInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';
import { rehydratePII, type RedactionEntry } from '../utils/piiRedactor.js';

// Reuse types from scan.ts
import type { ScanResult, BackendResponse } from './scan.js';

/**
 * Retry configuration (shared pattern with scan.ts)
 */
const RETRY_CONFIG = {
  maxRetries: 2,
  initialDelayMs: 200,
  maxDelayMs: 2000,
  backoffMultiplier: 2,
  retryableErrors: ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'fetch failed'],
};

function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    const errorStr = `${error.name} ${error.message} ${error.cause || ''}`;
    return RETRY_CONFIG.retryableErrors.some(e => errorStr.includes(e));
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  timeoutMs: number
): Promise<Response> {
  let lastError: Error | null = null;
  let delay = RETRY_CONFIG.initialDelayMs;

  for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      lastError = error instanceof Error ? error : new Error(String(error));

      if (lastError.name === 'AbortError' || !isRetryableError(error)) {
        throw lastError;
      }

      if (attempt < RETRY_CONFIG.maxRetries) {
        console.warn(`Response scan failed (attempt ${attempt + 1}/${RETRY_CONFIG.maxRetries + 1}), retrying in ${delay}ms: ${lastError.message}`);
        await sleep(delay);
        delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
      }
    }
  }

  throw lastError || new Error('Fetch failed after retries');
}

export interface PIIToken {
  token: string;
  original: string;
  type: string;
}

export interface ScanResponseInput {
  response: string;
  original_prompt?: string;
  pii_tokens?: PIIToken[];
}

/**
 * scan_response result — extends SanitizedResponse with optional rehydrated text
 */
export type ScanResponseResult = SanitizedResponse & {
  rehydrated_response?: string;
};

const MAX_CONTENT_SIZE = 100 * 1024; // 100KB

/**
 * Scans an LLM response for security threats.
 * Sends both the original prompt and response to the backend so L8 Response
 * Intelligence can perform PII diff, topic mismatch, and system prompt leak detection.
 *
 * When pii_tokens is provided (from scan_prompt's redact_pii), the response is
 * rehydrated after scanning — tokens like [EMAIL_1] are replaced with originals.
 */
export async function scanResponse(input: ScanResponseInput, customerId: string = 'anonymous'): Promise<ScanResponseResult> {
  const requestId = generateRequestId();
  const startTime = Date.now();

  const totalSize = input.response.length + (input.original_prompt?.length || 0);
  if (totalSize > MAX_CONTENT_SIZE) {
    const internalResult: ScanResult = {
      safe: false,
      threatLevel: 'error',
      confidence: 1.0,
      recommendedAction: 'block',
      violations: [{
        threatType: 'size_limit_exceeded',
        severity: 'high',
        confidence: 1.0,
        action: 'block',
        detectedBy: 'client_validation',
        message: `Content too large (${Math.round(totalSize / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        policyId: 'pol-size-limit',
        policyName: 'Content Size Limit',
      }],
      summary: {
        totalViolations: 1,
        criticalCount: 0,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        blockedCount: 1,
        flaggedCount: 0,
      },
      performance: {
        totalScanTimeMs: Date.now() - startTime,
        policiesEvaluated: 0,
        llmAnalysisUsed: false,
        cacheHits: 0,
      },
      metadata: {
        scanTimeMs: Date.now() - startTime,
        timedOut: false,
        scanType: 'response',
      },
    };

    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
    return sanitizeScanResult(internalResult, requestId);
  }

  try {
    // Neutralize PII before sending to backend.
    // Replace both tokens ([EMAIL_1]) AND original PII values (john@acme.com)
    // with [REDACTED] so the backend doesn't flag them as threats.
    let responseToScan = input.response;
    let promptToScan = input.original_prompt || '';
    if (input.pii_tokens?.length) {
      for (const t of input.pii_tokens) {
        // Replace token placeholders ([EMAIL_1] → [REDACTED])
        responseToScan = responseToScan.split(t.token).join('[REDACTED]');
        promptToScan = promptToScan.split(t.token).join('[REDACTED]');
        // Replace original PII values (john@acme.com → [REDACTED])
        // The original_prompt may contain raw PII that was redacted client-side
        if (t.original) {
          promptToScan = promptToScan.split(t.original).join('[REDACTED]');
          responseToScan = responseToScan.split(t.original).join('[REDACTED]');
        }
      }
    }

    const response = await fetchWithRetry(
      `${config.backendUrl}/scan`,
      {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          prompt: promptToScan,
          response: responseToScan,
          scan_type: 'full',
        }),
      },
      config.scanTimeoutMs
    );

    if (!response.ok) {
      console.error(`Response scan backend returned ${response.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error');
      logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
      return sanitizeScanResult(internalResult, requestId);
    }

    const data = await response.json() as BackendResponse;
    const internalResult = transformBackendResponse(data, Date.now() - startTime);

    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));

    const sanitized = sanitizeScanResult(internalResult, requestId);

    // Rehydrate PII tokens if provided and response is safe
    if (input.pii_tokens?.length && !sanitized.blocked) {
      const redactionEntries: RedactionEntry[] = input.pii_tokens.map((t, i) => ({
        token: t.token,
        original: t.original,
        type: t.type,
        position: i,
      }));
      return {
        ...sanitized,
        rehydrated_response: rehydratePII(input.response, redactionEntries),
      };
    }

    return sanitized;

  } catch (error) {
    let errorMessage = 'Scan error';

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        console.warn(`Response scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
        errorMessage = 'Analysis timeout';
      } else {
        console.error(`Response scan failed: ${error.name}: ${error.message}`);
        if (error.cause) console.error('Cause:', error.cause);
        errorMessage = `${error.name}: ${error.message}`;
      }
    } else {
      console.error('Response scan failed with non-Error:', error);
    }

    const internalResult = createFailClosedResponse(Date.now() - startTime, errorMessage);
    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
    return sanitizeScanResult(internalResult, requestId);
  }
}

/**
 * Transforms backend response to standardized format
 */
function transformBackendResponse(data: BackendResponse, scanTimeMs: number): ScanResult {
  const violations = (data.violations || []).map((v) => ({
    threatType: v.threat_type || 'unknown',
    severity: v.severity || 'medium',
    confidence: v.confidence ?? 0.8,
    action: v.action || 'flag',
    detectedBy: v.detected_by || 'unknown',
    message: v.ai_reasoning || v.policy_name || v.threat_type || 'Security violation detected',
    policyId: v.policy_id || 'unknown',
    policyName: v.policy_name || 'Unknown Policy',
    scanStage: v.scan_stage,
    matchedPattern: v.pattern,
  }));

  const summary = {
    totalViolations: violations.length,
    criticalCount: violations.filter(v => v.severity === 'critical').length,
    highCount: violations.filter(v => v.severity === 'high').length,
    mediumCount: violations.filter(v => v.severity === 'medium').length,
    lowCount: violations.filter(v => v.severity === 'low').length,
    blockedCount: violations.filter(v => v.action === 'block').length,
    flaggedCount: violations.filter(v => v.action === 'flag').length,
  };

  const maxConfidence = violations.length > 0
    ? Math.max(...violations.map(v => v.confidence))
    : 0;

  let recommendedAction: 'allow' | 'flag' | 'redact' | 'block' = 'allow';
  if (summary.blockedCount > 0 || summary.criticalCount > 0) {
    recommendedAction = 'block';
  } else if (violations.some(v => v.action === 'redact')) {
    recommendedAction = 'redact';
  } else if (summary.flaggedCount > 0 || summary.highCount > 0 || summary.mediumCount > 0) {
    recommendedAction = 'flag';
  }

  const llmAnalysis = data.llm_analysis ? {
    analyzed: data.llm_analysis.analyzed,
    isMalicious: data.llm_analysis.is_malicious,
    confidence: data.llm_analysis.confidence,
    threatType: data.llm_analysis.threat_type,
    reasoning: data.llm_analysis.reasoning,
    detectedBy: data.llm_analysis.detected_by,
    analysisTimeMs: data.llm_analysis.analysis_time_ms,
  } : undefined;

  return {
    safe: data.safe,
    threatLevel: data.threat_level || 'none',
    confidence: maxConfidence,
    recommendedAction,
    violations,
    summary,
    llmAnalysis,
    performance: {
      totalScanTimeMs: data.performance_metrics?.total_scan_time_ms || scanTimeMs,
      policiesEvaluated: data.performance_metrics?.policies_evaluated || 0,
      llmAnalysisUsed: data.performance_metrics?.llm_analysis_used || false,
      cacheHits: data.performance_metrics?.cache_hits || 0,
    },
    metadata: {
      scanTimeMs,
      timedOut: false,
      scanType: 'response',
    },
  };
}

function createFailClosedResponse(scanTimeMs: number, reason: string): ScanResult {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 1.0,
    recommendedAction: 'block',
    violations: [{
      threatType: 'scan_error',
      severity: 'high',
      confidence: 1.0,
      action: 'block',
      detectedBy: 'fail_closed_policy',
      message: `Response scan could not complete: ${reason}. Blocking as precaution.`,
      policyId: 'pol-fail-closed',
      policyName: 'Fail-Closed Security Policy',
    }],
    summary: {
      totalViolations: 1,
      criticalCount: 0,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      blockedCount: 1,
      flaggedCount: 0,
    },
    performance: {
      totalScanTimeMs: scanTimeMs,
      policiesEvaluated: 0,
      llmAnalysisUsed: false,
      cacheHits: 0,
    },
    metadata: {
      scanTimeMs,
      timedOut: reason.includes('timeout'),
      scanType: 'response',
    },
  };
}

/**
 * MCP Tool definition for scan_response
 */
export const scanResponseTool = {
  name: 'scan_response',
  description: `Scans an LLM-generated response before showing it to the user.

Detects:
- System prompt leaks (LLM revealing its instructions)
- Unexpected PII in output (PII not present in the original prompt)
- Toxic or hostile language in generated content
- Topic drift (response diverges from prompt intent)
- Policy violations in generated content

Provide the original_prompt for best results — it enables PII diff analysis
and topic mismatch detection.

When pii_tokens is provided (from scan_prompt with redact_pii=true), the response
is rehydrated after scanning. Tokens like [EMAIL_1] are replaced with the original
values. The rehydrated text is returned as rehydrated_response.

Returns:
- blocked: true/false
- threat_type: category of threat detected
- severity/confidence/guidance: security assessment details
- rehydrated_response: (when pii_tokens provided and response is safe) text with PII restored
- request_id: unique identifier`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      response: {
        type: 'string',
        description: 'The LLM-generated response to scan for security threats',
      },
      original_prompt: {
        type: 'string',
        description: 'The original prompt that generated this response. Enables PII diff and topic mismatch detection.',
      },
      pii_tokens: {
        type: 'array',
        description: 'PII token map from scan_prompt(redact_pii=true). When provided, tokens in the response are rehydrated with original values after scanning.',
        items: {
          type: 'object',
          properties: {
            token: { type: 'string', description: 'The token placeholder, e.g. [EMAIL_1]' },
            original: { type: 'string', description: 'The original PII value' },
            type: { type: 'string', description: 'PII type, e.g. email, phone, ssn' },
          },
          required: ['token', 'original', 'type'],
        },
      },
    },
    required: ['response'],
  },
  annotations: {
    title: 'Scan Response',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
