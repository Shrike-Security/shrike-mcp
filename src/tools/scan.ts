/**
 * scan_prompt Tool
 * Scans text for PII, injection attacks, and toxicity
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeScanResult,
  logInternalDetails,
  extractScanInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';
import {
  redactPII,
  getRedactionSummary,
  type RedactionEntry,
} from '../utils/piiRedactor.js';

/**
 * Phase 8b: Client-side size limits to fail fast before network round-trip.
 * These limits match the backend limits for consistency.
 */
const MAX_CONTENT_SIZE = 100 * 1024; // 100KB - matches backend MaxRequestBodySize

/**
 * Retry configuration for handling cold-start and transient failures
 */
const RETRY_CONFIG = {
  maxRetries: 2,                    // Total attempts = 3 (initial + 2 retries)
  initialDelayMs: 200,              // Start with 200ms delay
  maxDelayMs: 2000,                 // Cap at 2 seconds
  backoffMultiplier: 2,             // Exponential backoff: 200ms, 400ms, 800ms...
  retryableErrors: ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'fetch failed'],
};

/**
 * Checks if an error is retryable (transient network/cold-start issue)
 */
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    const errorStr = `${error.name} ${error.message} ${error.cause || ''}`;
    return RETRY_CONFIG.retryableErrors.some(e => errorStr.includes(e));
  }
  return false;
}

/**
 * Sleep helper for retry delays
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Fetch with retry for cold-start resilience
 */
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

      // Don't retry on abort (timeout) or non-retryable errors
      if (lastError.name === 'AbortError' || !isRetryableError(error)) {
        throw lastError;
      }

      // Log retry attempt
      if (attempt < RETRY_CONFIG.maxRetries) {
        console.warn(`Scan request failed (attempt ${attempt + 1}/${RETRY_CONFIG.maxRetries + 1}), retrying in ${delay}ms: ${lastError.message}`);
        await sleep(delay);
        delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
      }
    }
  }

  throw lastError || new Error('Fetch failed after retries');
}

export interface ScanInput {
  content: string;
  context?: string;
  redact_pii?: boolean;
}

/**
 * PII redaction metadata returned when redact_pii is enabled.
 * Tokens map to originals so the caller can rehydrate LLM responses.
 */
export interface PIIRedactionInfo {
  pii_detected: boolean;
  redacted_content: string;
  redaction_count: number;
  summary: Record<string, number>;
  tokens: Array<{
    token: string;
    original: string;
    type: string;
  }>;
}

/**
 * scan_prompt response — extends SanitizedResponse with optional PII redaction data
 */
export type ScanPromptResponse = SanitizedResponse & {
  pii_redaction?: PIIRedactionInfo;
};

/**
 * Standardized violation detail with full security metadata
 */
export interface Violation {
  /** Threat category: prompt_injection, pii, jailbreak, toxicity, etc. */
  threatType: string;
  /** Severity level: critical, high, medium, low */
  severity: string;
  /** Confidence score 0.0-1.0 */
  confidence: number;
  /** Recommended action: block, redact, flag, allow */
  action: string;
  /** Detection layer: regex, llm_only, both, encoding_*, visual, threatsense, etc. */
  detectedBy: string;
  /** Human-readable explanation */
  message: string;
  /** Policy that triggered: pol-prompt-injection, llm-semantic-analysis, etc. */
  policyId: string;
  /** Policy name */
  policyName: string;
  /** Scan stage: prompt, response */
  scanStage?: string;
  /** Matched text (if available and safe to expose) */
  matchedPattern?: string;
}

/**
 * LLM analysis metadata
 */
export interface LLMAnalysis {
  /** Whether LLM analysis was performed */
  analyzed: boolean;
  /** LLM's threat assessment */
  isMalicious: boolean;
  /** LLM confidence 0.0-1.0 */
  confidence: number;
  /** Threat type identified by LLM */
  threatType: string;
  /** LLM's reasoning explanation */
  reasoning: string;
  /** How threat was detected: llm_only, both, regex_only, none */
  detectedBy: string;
  /** LLM analysis time in ms */
  analysisTimeMs: number;
}

/**
 * Performance metrics for monitoring
 */
export interface PerformanceMetrics {
  /** Total scan time in ms */
  totalScanTimeMs: number;
  /** Number of policies evaluated */
  policiesEvaluated: number;
  /** Whether LLM was used */
  llmAnalysisUsed: boolean;
  /** Cache hits for performance */
  cacheHits: number;
}

/**
 * Standardized scan result with rich metadata for security decisions
 */
export interface ScanResult {
  /** Primary safety verdict */
  safe: boolean;
  /** Overall threat level: none, low, medium, high, critical */
  threatLevel: string;
  /** Aggregated confidence score (highest violation confidence) */
  confidence: number;
  /** Recommended action based on highest severity violation */
  recommendedAction: 'allow' | 'flag' | 'redact' | 'block';
  /** Detailed violation list */
  violations: Violation[];
  /** Summary counts by category */
  summary: {
    totalViolations: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    blockedCount: number;
    flaggedCount: number;
  };
  /** LLM analysis details (if performed) */
  llmAnalysis?: LLMAnalysis;
  /** Performance metrics */
  performance: PerformanceMetrics;
  /** Scan metadata */
  metadata: {
    scanTimeMs: number;
    timedOut: boolean;
    backendVersion?: string;
    scanType: string;
  };
}

/**
 * Backend response type mapping
 */
export interface BackendResponse {
  safe: boolean;
  threat_level?: string;
  violations?: Array<{
    policy_id: string;
    policy_name: string;
    action: string;
    severity: string;
    threat_type: string;
    confidence?: number;
    ai_reasoning?: string;
    matched_text?: string;
    pattern?: string;
    scan_stage?: string;
    detected_by?: string;
  }>;
  performance_metrics?: {
    total_scan_time_ms: number;
    policies_evaluated: number;
    llm_analysis_used: boolean;
    cache_hits: number;
  };
  llm_analysis?: {
    analyzed: boolean;
    is_malicious: boolean;
    confidence: number;
    threat_type: string;
    reasoning: string;
    detected_by: string;
    analysis_time_ms: number;
  };
}

/**
 * Scans content for security threats
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance
 *
 * @param input - The content to scan
 * @param customerId - Customer identifier for logging (default: 'anonymous')
 * @returns Sanitized response with threat_type, confidence bucket, and guidance
 */
export async function scanPrompt(input: ScanInput, customerId: string = 'anonymous'): Promise<ScanPromptResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();

  // Phase 8b: Client-side size validation to fail fast
  const totalSize = input.content.length + (input.context?.length || 0);
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
        scanType: 'validation',
      },
    };

    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
    return sanitizeScanResult(internalResult, requestId);
  }

  // PII redaction: redact before sending to backend so PII never leaves MCP
  let contentToScan = input.content;
  let contextToScan = input.context || '';
  let piiRedaction: PIIRedactionInfo | undefined;

  if (input.redact_pii) {
    const contentResult = redactPII(input.content);
    const contextResult = input.context ? redactPII(input.context) : null;

    contentToScan = contentResult.redactedText;
    if (contextResult) {
      contextToScan = contextResult.redactedText;
    }

    // Merge redactions from content and context
    const allRedactions: RedactionEntry[] = [
      ...contentResult.redactions,
      ...(contextResult?.redactions || []),
    ];
    const allDetected = contentResult.piiDetected || (contextResult?.piiDetected ?? false);

    if (allDetected) {
      piiRedaction = {
        pii_detected: true,
        redacted_content: contentToScan,
        redaction_count: allRedactions.length,
        summary: getRedactionSummary(allRedactions),
        tokens: allRedactions.map(r => ({
          token: r.token,
          original: r.original,
          type: r.type,
        })),
      };

      console.error(`[PII] Redacted ${allRedactions.length} PII items before scan (request=${requestId})`);
    }
  }

  // Neutralize PII tokens before sending to backend to prevent FP on [EMAIL_1] etc.
  let promptForBackend = contentToScan;
  let contextForBackend = contextToScan;
  if (piiRedaction?.tokens?.length) {
    for (const t of piiRedaction.tokens) {
      promptForBackend = promptForBackend.split(t.token).join('[REDACTED]');
      contextForBackend = contextForBackend.split(t.token).join('[REDACTED]');
    }
  }

  try {
    // Use fetchWithRetry for cold-start resilience
    const response = await fetchWithRetry(
      `${config.backendUrl}/scan`,
      {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          prompt: promptForBackend,
          conversation_history: contextForBackend,
          scan_type: 'full',
        }),
      },
      config.scanTimeoutMs
    );

    if (!response.ok) {
      console.error(`Scan backend returned ${response.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error');
      logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
      return { ...sanitizeScanResult(internalResult, requestId), pii_redaction: piiRedaction };
    }

    const data = await response.json() as BackendResponse;
    const internalResult = transformBackendResponse(data, Date.now() - startTime);

    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));

    return { ...sanitizeScanResult(internalResult, requestId), pii_redaction: piiRedaction };

  } catch (error) {
    let internalResult: ScanResult;
    let errorMessage = 'Scan error';

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        console.warn(`Scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
        errorMessage = 'Analysis timeout';
      } else {
        console.error(`Scan failed: ${error.name}: ${error.message}`);
        if (error.cause) console.error('Cause:', error.cause);
        errorMessage = `${error.name}: ${error.message}`;
      }
    } else {
      console.error('Scan failed with non-Error:', error);
    }

    internalResult = createFailClosedResponse(Date.now() - startTime, errorMessage);
    logInternalDetails(extractScanInternalDetails(internalResult, requestId, customerId));
    return { ...sanitizeScanResult(internalResult, requestId), pii_redaction: piiRedaction };
  }
}

/**
 * Transforms backend response to standardized MCP format
 */
function transformBackendResponse(data: BackendResponse, scanTimeMs: number): ScanResult {
  const violations: Violation[] = (data.violations || []).map((v) => ({
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

  // Calculate summary counts
  const summary = {
    totalViolations: violations.length,
    criticalCount: violations.filter(v => v.severity === 'critical').length,
    highCount: violations.filter(v => v.severity === 'high').length,
    mediumCount: violations.filter(v => v.severity === 'medium').length,
    lowCount: violations.filter(v => v.severity === 'low').length,
    blockedCount: violations.filter(v => v.action === 'block').length,
    flaggedCount: violations.filter(v => v.action === 'flag').length,
  };

  // Determine highest confidence from violations
  const maxConfidence = violations.length > 0
    ? Math.max(...violations.map(v => v.confidence))
    : 0;

  // Determine recommended action based on highest severity
  let recommendedAction: 'allow' | 'flag' | 'redact' | 'block' = 'allow';
  if (summary.blockedCount > 0 || summary.criticalCount > 0) {
    recommendedAction = 'block';
  } else if (violations.some(v => v.action === 'redact')) {
    recommendedAction = 'redact';
  } else if (summary.flaggedCount > 0 || summary.highCount > 0 || summary.mediumCount > 0) {
    recommendedAction = 'flag';
  }

  // Transform LLM analysis if present
  const llmAnalysis: LLMAnalysis | undefined = data.llm_analysis ? {
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
      scanType: 'full',
    },
  };
}

/**
 * Creates a fail-CLOSED response when scanning fails
 * SECURITY: Timeouts and errors are treated as unsafe to prevent bypasses
 */
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
      message: `Security scan could not complete: ${reason}. Blocking as precaution.`,
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
      scanType: 'full',
    },
  };
}

/**
 * MCP Tool definition for scan_prompt
 */
export const scanPromptTool = {
  name: 'scan_prompt',
  description: `Scans text for security threats including PII, prompt injection, jailbreak attempts, and toxicity.

Returns a security assessment with:
- blocked: true/false - whether the content was blocked
- threat_type: category of threat detected (prompt_injection, jailbreak, pii_exposure, etc.)
- severity: critical/high/medium/low
- confidence: high/medium/low
- guidance: actionable explanation of what was detected
- request_id: unique identifier for this scan

If blocked=false, only request_id is returned (content is safe).

When redact_pii=true, PII is redacted client-side before scanning. The response includes:
- pii_redaction.redacted_content: text with PII replaced by tokens like [EMAIL_1]
- pii_redaction.tokens: array of {token, original, type} for rehydrating LLM responses
PII never leaves the MCP process when redaction is enabled.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      content: {
        type: 'string',
        description: 'The text content to scan for security threats',
      },
      context: {
        type: 'string',
        description: 'Optional conversation history or context for better analysis',
      },
      redact_pii: {
        type: 'boolean',
        description: 'When true, PII is redacted before scanning. Response includes redacted_content and tokens for rehydration.',
      },
    },
    required: ['content'],
  },
};
