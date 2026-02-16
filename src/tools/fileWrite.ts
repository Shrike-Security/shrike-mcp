/**
 * scan_file_write Tool
 * Scans file write operations for security threats
 *
 * ALIGNED WITH BACKEND: This tool now calls the backend's /scan/specialized
 * endpoint instead of using local regex, ensuring consistent security coverage
 * with the SDKs (Go, Python, TypeScript).
 *
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance.
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeFileWriteResult,
  logInternalDetails,
  extractSpecializedInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';

/**
 * Phase 8b: Client-side size limits for file writes.
 * File writes can be larger than scans since they're actual file content.
 */
const MAX_FILE_CONTENT_SIZE = 1024 * 1024; // 1MB for file writes

export interface FileWriteInput {
  path: string;
  content: string;
  mode?: 'create' | 'overwrite' | 'append';
}

export interface FileWriteResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'block';
  issues: Array<{
    type: string;
    severity: string;
    message: string;
    pattern?: string;
    location?: 'path' | 'content';
  }>;
  metadata: {
    scanTimeMs: number;
    pathLength: number;
    contentLength: number;
    fileExtension: string;
  };
}

/**
 * Backend specialized scan response type
 */
interface BackendSpecializedResponse {
  safe: boolean;
  threat_type?: string;
  severity?: string;
  reason?: string;
  confidence: number;
  content_type: string;
  scan_time_ms: number;
}

/**
 * Extracts file extension from path
 */
function getFileExtension(path: string): string {
  const match = path.match(/\.([^./\\]+)$/);
  return match ? match[1].toLowerCase() : '';
}

/**
 * Maps severity to threat level
 */
function mapSeverityToThreatLevel(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'none';
  }
}

/**
 * Maps severity to recommended action
 */
function mapSeverityToAction(severity: string | undefined): 'allow' | 'flag' | 'block' {
  switch (severity?.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'block';
    case 'medium':
      return 'flag';
    default:
      return 'allow';
  }
}

/**
 * Creates a fail-closed response when scanning fails
 * SECURITY: Timeouts and errors are treated as unsafe to prevent bypasses
 */
function createFailClosedResponse(
  scanTimeMs: number,
  reason: string,
  pathLength: number,
  contentLength: number,
  fileExtension: string
): FileWriteResult {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 1.0,
    recommendedAction: 'block',
    issues: [{
      type: 'scan_error',
      severity: 'high',
      message: `Security scan could not complete: ${reason}. Blocking as precaution.`,
    }],
    metadata: {
      scanTimeMs,
      pathLength,
      contentLength,
      fileExtension,
    },
  };
}

/**
 * Scans a file write operation for security issues by calling the backend API
 * This ensures consistent security coverage with the SDKs
 *
 * @param input - The file write operation to scan
 * @param customerId - Customer identifier for logging (default: 'anonymous')
 * @returns Sanitized response with threat_type, confidence bucket, and guidance
 */
export async function scanFileWrite(input: FileWriteInput, customerId: string = 'anonymous'): Promise<SanitizedResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  const pathLength = input.path.length;
  const contentLength = input.content.length;
  const fileExtension = getFileExtension(input.path) || 'none';

  // Phase 8b: Client-side size validation for file content
  if (input.content.length > MAX_FILE_CONTENT_SIZE) {
    const internalResult: FileWriteResult = {
      safe: false,
      threatLevel: 'error',
      confidence: 1.0,
      recommendedAction: 'block',
      issues: [{
        type: 'size_limit',
        severity: 'high',
        message: `File content too large (${Math.round(input.content.length / 1024)}KB > ${MAX_FILE_CONTENT_SIZE / 1024}KB limit)`,
        location: 'content',
      }],
      metadata: {
        scanTimeMs: Date.now() - startTime,
        pathLength,
        contentLength,
        fileExtension,
      },
    };

    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
    } else {
      console.error(`[file] ${requestId} safe=false action=block reason=size_limit time=${Date.now() - startTime}ms`);
    }
    return sanitizeFileWriteResult(internalResult, requestId);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    const issues: FileWriteResult['issues'] = [];
    let overallSafe = true;
    let highestSeverity: string | undefined;
    let totalConfidence = 1.0;

    // Step 1: Scan the file path
    const pathResponse = await fetch(`${config.backendUrl}/api/scan/specialized`, {
      method: 'POST',
      headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      body: JSON.stringify({
        content: input.path,
        content_type: 'file_path',
      }),
      signal: controller.signal,
    });

    if (!pathResponse.ok) {
      clearTimeout(timeoutId);
      console.error(`File path scan backend returned ${pathResponse.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', pathLength, contentLength, fileExtension);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
      } else {
        console.error(`[file] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeFileWriteResult(internalResult, requestId);
    }

    const pathData = await pathResponse.json() as BackendSpecializedResponse;

    if (!pathData.safe) {
      overallSafe = false;
      highestSeverity = pathData.severity;
      totalConfidence = Math.min(totalConfidence, pathData.confidence);
      issues.push({
        type: pathData.threat_type || 'path_violation',
        severity: pathData.severity || 'high',
        message: pathData.reason || 'File path security issue detected',
        location: 'path',
      });
    }

    // Step 2: Scan the file content (path + content together for context)
    const contentResponse = await fetch(`${config.backendUrl}/api/scan/specialized`, {
      method: 'POST',
      headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      body: JSON.stringify({
        content: input.path,
        content_type: 'file_content',
        context: {
          content: input.content,  // Backend expects "content" key, not "file_content"
        },
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!contentResponse.ok) {
      console.error(`File content scan backend returned ${contentResponse.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', pathLength, contentLength, fileExtension);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
      } else {
        console.error(`[file] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeFileWriteResult(internalResult, requestId);
    }

    const contentData = await contentResponse.json() as BackendSpecializedResponse;

    if (!contentData.safe) {
      overallSafe = false;
      // Update highest severity if content issue is more severe
      if (!highestSeverity || compareSeverity(contentData.severity, highestSeverity) > 0) {
        highestSeverity = contentData.severity;
      }
      totalConfidence = Math.min(totalConfidence, contentData.confidence);
      issues.push({
        type: contentData.threat_type || 'content_violation',
        severity: contentData.severity || 'high',
        message: contentData.reason || 'File content security issue detected',
        location: 'content',
      });
    }

    const scanTimeMs = Date.now() - startTime;

    // Prioritize content issues over path issues — content threats (reverse shell,
    // secrets, PII) are more specific than path-level issues (sensitive extension).
    // This ensures sanitizeFileWriteResult picks the most actionable threat type.
    issues.sort((a, b) => {
      if (a.location === 'content' && b.location === 'path') return -1;
      if (a.location === 'path' && b.location === 'content') return 1;
      return compareSeverity(a.severity, b.severity) * -1; // higher severity first
    });

    const internalResult: FileWriteResult = {
      safe: overallSafe,
      threatLevel: overallSafe ? 'none' : mapSeverityToThreatLevel(highestSeverity),
      confidence: totalConfidence,
      recommendedAction: overallSafe ? 'allow' : mapSeverityToAction(highestSeverity),
      issues,
      metadata: {
        scanTimeMs,
        pathLength,
        contentLength,
        fileExtension,
      },
    };

    // Log scan result
    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
    } else {
      console.error(`[file] ${requestId} safe=${internalResult.safe} action=${internalResult.recommendedAction} time=${Date.now() - startTime}ms`);
    }

    // Return sanitized response (protects IP)
    return sanitizeFileWriteResult(internalResult, requestId);

  } catch (error) {
    clearTimeout(timeoutId);

    let internalResult: FileWriteResult;
    if (error instanceof Error && error.name === 'AbortError') {
      console.warn(`File scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Analysis timeout', pathLength, contentLength, fileExtension);
    } else {
      console.error(`File scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Scan error', pathLength, contentLength, fileExtension);
    }

    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
    } else {
      console.error(`[file] ${requestId} safe=false action=block reason=error time=${Date.now() - startTime}ms`);
    }
    return sanitizeFileWriteResult(internalResult, requestId);
  }
}

/**
 * Compares two severity levels
 * Returns positive if a > b, negative if a < b, 0 if equal
 */
function compareSeverity(a: string | undefined, b: string | undefined): number {
  const order: Record<string, number> = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1,
  };
  const aVal = order[a?.toLowerCase() || ''] || 0;
  const bVal = order[b?.toLowerCase() || ''] || 0;
  return aVal - bVal;
}

/**
 * MCP Tool definition for scan_file_write
 */
export const scanFileWriteTool = {
  name: 'scan_file_write',
  description: `Scans a file write operation before execution for security threats.

Checks:
- Sensitive file paths (.env, credentials, SSH keys, certificates)
- Path traversal attacks (../, system directories)
- PII in content (SSN, credit cards, emails)
- Secrets in content (API keys, passwords, tokens)
- Malicious code patterns (reverse shells, fork bombs)

Returns:
- blocked: true/false
- threat_type: path_traversal, secrets_exposure, etc.
- severity: critical/high/medium/low
- confidence: high/medium/low
- guidance: actionable explanation
- request_id: unique identifier`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      path: {
        type: 'string',
        description: 'The target file path to write to',
      },
      content: {
        type: 'string',
        description: 'The content to be written to the file',
      },
      mode: {
        type: 'string',
        enum: ['create', 'overwrite', 'append'],
        description: 'Write mode (default: overwrite)',
      },
    },
    required: ['path', 'content'],
  },
  annotations: {
    title: 'Scan File Write',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
