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

import { config, getAuthHeaders, getSessionId, getAgentId } from '../config.js';
import {
  generateRequestId,
  sanitizeFileWriteResult,
  logInternalDetails,
  extractSpecializedInternalDetails,
  type SanitizedResponse,
  type SessionState,
} from '../utils/responseFormatter.js';
import { CircuitOpenError, scanCircuitBreaker } from '../utils/circuitBreaker.js';

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
  approvalInfo?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
  };
  /** L9 session outcome contract — see responseFormatter.SessionState. */
  sessionState?: SessionState;
  /** Cooperative Governance refuse tier. Forwarded to top-level `refuse_tier`. */
  refuseTier?: 'allow' | 'warn' | 'require_approval' | 'block';
  /** Recovery guidance block. Forwarded to top-level `recovery`. */
  recovery?: { instruction?: string; available_tools?: string[]; patterns_triggered?: string[] };
  /** Specialized scan input type — forwarded to top-level `content_type`. */
  contentType?: string;
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
  approval_info?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
    // Block-override threat context
    threat_type?: string;
    severity?: string;
    owasp_category?: string;
    risk_factors?: string[];
    original_action?: string;
  };
  /** L9 session outcome contract — see responseFormatter.SessionState. */
  session_state?: SessionState;
  /** Cooperative Governance refuse tier. */
  refuse_tier?: 'allow' | 'warn' | 'require_approval' | 'block';
  /** Recovery guidance block. */
  recovery?: { instruction?: string; available_tools?: string[]; patterns_triggered?: string[] };
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
  const effective_session_id = (input as any).session_id || getSessionId();
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
    return sanitizeFileWriteResult(internalResult, requestId, effective_session_id, 'scan_file_write');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    const issues: FileWriteResult['issues'] = [];
    let overallSafe = true;
    let highestSeverity: string | undefined;
    let totalConfidence = 1.0;

    // Step 1: Scan the file path (through circuit breaker)
    const pathResponse = await scanCircuitBreaker.execute(() =>
      fetch(`${config.backendUrl}/api/scan/specialized`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          content: input.path,
          content_type: 'file_path',
          context: {
            // Session identity — caller-supplied value wins; the MCP client's
            // process-level SESSION_ID / AGENT_ID are fallbacks only.
            session_id: effective_session_id,
            agent_id: (input as any).agent_id || getAgentId(),
            parent_agent_id: (input as any).parent_agent_id || '',
            task_chain: (input as any).task_chain || '',
            // Server-managed integrity field — cannot be overridden by caller.
            source_application: 'shrike-mcp',
          },
        }),
        signal: controller.signal,
      })
    );

    if (!pathResponse.ok) {
      clearTimeout(timeoutId);
      console.error(`File path scan backend returned ${pathResponse.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', pathLength, contentLength, fileExtension);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
      } else {
        console.error(`[file] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeFileWriteResult(internalResult, requestId, effective_session_id, 'scan_file_write');
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

    // Step 2: Scan the file content (through circuit breaker)
    const contentResponse = await scanCircuitBreaker.execute(() =>
      fetch(`${config.backendUrl}/api/scan/specialized`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          content: input.path,
          content_type: 'file_content',
          context: {
            content: input.content,
            // Session identity — caller-supplied value wins; the MCP client's
            // process-level SESSION_ID / AGENT_ID are fallbacks only.
            session_id: effective_session_id,
            agent_id: (input as any).agent_id || getAgentId(),
            parent_agent_id: (input as any).parent_agent_id || '',
            task_chain: (input as any).task_chain || '',
            // Server-managed integrity field — cannot be overridden by caller.
            source_application: 'shrike-mcp',
          },
        }),
        signal: controller.signal,
      })
    );

    clearTimeout(timeoutId);

    if (!contentResponse.ok) {
      console.error(`File content scan backend returned ${contentResponse.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', pathLength, contentLength, fileExtension);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
      } else {
        console.error(`[file] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeFileWriteResult(internalResult, requestId, effective_session_id, 'scan_file_write');
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
      approvalInfo: contentData.approval_info || pathData.approval_info,
      // Session state is identical on path + content responses within one
      // scanFileWrite call — both requests carry the same session_id/agent_id
      // and hit the correlator on the same turn. Prefer content's when both
      // present to keep parity with approvalInfo's precedence.
      sessionState: contentData.session_state || pathData.session_state,
      refuseTier: contentData.refuse_tier || pathData.refuse_tier,
      recovery: contentData.recovery || pathData.recovery,
      contentType: contentData.content_type || pathData.content_type,
    };

    // Log scan result
    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_file_write'));
    } else {
      console.error(`[file] ${requestId} safe=${internalResult.safe} action=${internalResult.recommendedAction} time=${Date.now() - startTime}ms`);
    }

    // Return sanitized response (protects IP)
    return sanitizeFileWriteResult(internalResult, requestId, effective_session_id, 'scan_file_write');

  } catch (error) {
    clearTimeout(timeoutId);

    let internalResult: FileWriteResult;
    if (error instanceof CircuitOpenError) {
      console.error(`[file] ${requestId} circuit breaker OPEN — blocking (fail-closed)`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Security service unavailable (circuit breaker open)', pathLength, contentLength, fileExtension);
    } else if (error instanceof Error && error.name === 'AbortError') {
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
    return sanitizeFileWriteResult(internalResult, requestId, effective_session_id, 'scan_file_write');
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
  description: `Protective check on file operations — catches path traversal, leaked secrets, or sensitive paths before you write, so credentials don't leak through your hand.

Call this BEFORE writing any file to disk, storage, or output. Also call this when reading files from user-specified paths — path traversal attacks target both read and write operations.

DECISION LOGIC:
- If blocked=true: do NOT write the file. Return the user_message to the caller.
- If blocked=false: the file operation is safe to proceed.

Checks:
- Sensitive file paths (.env, credentials, SSH keys, certificates)
- Path traversal attacks (../, system directories)
- PII in content (SSN, credit cards, emails)
- Secrets in content (API keys, passwords, tokens)
- Malicious code patterns (reverse shells, fork bombs)

Enterprise context: Prevents agents from accidentally writing credentials to logs, committing secrets to repositories, or overwriting system files.

SESSION QUARANTINE (act plane): This tool is scan_class="act" and quarantine_gated=true. When threat_type is "session_locked", the session's accumulated risk from earlier turns has crossed the quarantine threshold. This tool refuses to authorize the requested side effect on that session; the detection cascade is skipped. Recovery: rotate to a new session_id (MCP 4.0.x auto-rotates on this verdict; manual callers can pass a fresh session_id in the tool arguments). reset_session is admin-restricted at this risk tier to preserve the correlation trail. The observe-plane tools (scan_prompt, scan_response) remain available — use them to inspect the payload you were about to send.

ERROR HANDLING: If this tool returns an error or is unavailable, default to BLOCKING the file operation. Do NOT write unscanned content.`,
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
      session_id: {
        type: 'string',
        description: 'Session identifier for multi-turn correlation.',
      },
      agent_id: {
        type: 'string',
        description: 'Your agent identifier for activity tracking.',
      },
      parent_agent_id: {
        type: 'string',
        description: 'Parent agent ID if you are a sub-agent (delegation chain tracking).',
      },
      task_chain: {
        type: 'string',
        description: 'Delegation path from root agent (e.g., "main→research→fetch").',
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
  
  // Shrike governance-plane classification. Placed in _meta (MCP's
  // explicit extension slot) rather than annotations, because
  // ToolAnnotationsSchema uses Zod $strip mode and drops unknown
  // fields at tools/list serialization. _meta is z.ZodRecord and
  // preserves arbitrary keys through the wire. Keys are prefixed with
  // 'shrike/' to namespace against other extensions.
  _meta: {
    'shrike/scan_class': 'act',
    'shrike/quarantine_gated': true,
    'shrike/contract_version': '2026-07-03',
  },
};
