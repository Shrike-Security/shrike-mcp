/**
 * scan_command Tool
 * Scans CLI commands for security threats before execution
 *
 * ALIGNED WITH BACKEND: This tool calls the backend's /api/scan/specialized
 * endpoint with content_type: "command", ensuring consistent security coverage
 * with the SDKs (Go, Python, TypeScript).
 *
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance.
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeCommandResult,
  logInternalDetails,
  extractSpecializedInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';

export interface CommandInput {
  command: string;
  shell?: string;
  working_directory?: string;
  execution_context?: string;
  piped_from?: string;
}

export interface CommandResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'block';
  issues: Array<{
    type: string;
    severity: string;
    message: string;
    pattern?: string;
  }>;
  metadata: {
    scanTimeMs: number;
    commandLength: number;
  };
  commandAnalysis?: {
    parsed_command: string;
    parsed_args: string[];
    pipe_chain?: string[];
    risk_factors: string[];
  };
  approvalInfo?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
    threat_type?: string;
    severity?: string;
    owasp_category?: string;
    risk_factors?: string[];
    original_action?: string;
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
  command_analysis?: {
    parsed_command: string;
    parsed_args: string[];
    pipe_chain?: string[];
    risk_factors: string[];
  };
  approval_info?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
    threat_type?: string;
    severity?: string;
    owasp_category?: string;
    risk_factors?: string[];
    original_action?: string;
  };
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
function createFailClosedResponse(scanTimeMs: number, reason: string, commandLength: number): CommandResult {
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
      commandLength,
    },
  };
}

/**
 * Scans a CLI command for security issues by calling the backend API
 *
 * @param input - The command to scan
 * @param customerId - Customer identifier for logging (default: 'anonymous')
 * @returns Sanitized response with threat_type, confidence bucket, and guidance
 */
export async function scanCommand(input: CommandInput, customerId: string = 'anonymous'): Promise<SanitizedResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  const commandLength = input.command.length;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    // Build context for backend
    const context: Record<string, string> = {};
    if (input.shell) {
      context.shell = input.shell;
    }
    if (input.working_directory) {
      context.working_directory = input.working_directory;
    }
    if (input.execution_context) {
      context.execution_context = input.execution_context;
    }
    if (input.piped_from) {
      context.piped_from = input.piped_from;
    }

    // Call backend specialized scan endpoint
    const response = await fetch(`${config.backendUrl}/api/scan/specialized`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        content: input.command,
        content_type: 'command',
        context: Object.keys(context).length > 0 ? context : undefined,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Command scan backend returned ${response.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', commandLength);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_command'));
      } else {
        console.error(`[command] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeCommandResult(internalResult, requestId, 'scan_command');
    }

    const data = await response.json() as BackendSpecializedResponse;
    const scanTimeMs = Date.now() - startTime;

    // Transform backend response to internal format
    const issues: CommandResult['issues'] = [];
    if (!data.safe && data.threat_type) {
      issues.push({
        type: data.threat_type,
        severity: data.severity || 'high',
        message: data.reason || 'Command security issue detected',
      });
    }

    const internalResult: CommandResult = {
      safe: data.safe,
      threatLevel: mapSeverityToThreatLevel(data.severity),
      confidence: data.confidence,
      recommendedAction: data.safe ? 'allow' : mapSeverityToAction(data.severity),
      issues,
      metadata: {
        scanTimeMs: data.scan_time_ms || scanTimeMs,
        commandLength,
      },
      commandAnalysis: data.command_analysis,
      approvalInfo: data.approval_info,
    };

    // Log scan result
    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_command'));
    } else {
      console.error(`[command] ${requestId} safe=${internalResult.safe} action=${internalResult.recommendedAction} time=${Date.now() - startTime}ms`);
    }

    // Return sanitized response (protects IP)
    return sanitizeCommandResult(internalResult, requestId, 'scan_command');

  } catch (error) {
    clearTimeout(timeoutId);

    let internalResult: CommandResult;
    if (error instanceof Error && error.name === 'AbortError') {
      console.warn(`Command scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Analysis timeout', commandLength);
    } else {
      console.error(`Command scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Scan error', commandLength);
    }

    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_command'));
    } else {
      console.error(`[command] ${requestId} safe=false action=block reason=error time=${Date.now() - startTime}ms`);
    }
    return sanitizeCommandResult(internalResult, requestId, 'scan_command');
  }
}

/**
 * MCP Tool definition for scan_command
 */
export const scanCommandTool = {
  name: 'scan_command',
  description: `Call this BEFORE executing any CLI command generated by an LLM, constructed from user input, or involving system operations.

DECISION LOGIC:
- If blocked=true: do NOT execute the command. Return the user_message and log audit.scan_id for security review.
- If blocked=false: the command is safe to execute.
- If action=require_approval: pause execution, present approval_context to the user, then call check_approval with the approval_id.

Checks for:
- Data exfiltration (curl -d @file, scp to remote, pipe chains like cat .env | curl)
- Destructive operations (rm -rf /, dd to device, mkfs)
- Remote code execution (reverse shells, curl | sh, nc -e)
- Privilege escalation (chmod u+s, sudoers modification)
- Secret exposure (cat .env, echo $API_KEY, reading credentials files)
- Obfuscated commands (base64 decode | sh, eval with expansion)
- Pipe chain analysis (cross-command threat detection for individually safe commands)

Common safe commands (ls, git, npm, docker build, go test, etc.) pass through without triggering.

Enterprise context: Critical for any agent with shell/subprocess access. Prevents both malicious and accidental damage from LLM-generated commands.

ERROR HANDLING: If this tool returns an error or is unavailable, default to BLOCKING the command. Do NOT execute unscanned commands.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      command: {
        type: 'string',
        description: 'The CLI command to scan before execution',
      },
      shell: {
        type: 'string',
        enum: ['bash', 'sh', 'zsh', 'fish', 'powershell', 'cmd'],
        description: 'Shell interpreter (default: bash)',
      },
      working_directory: {
        type: 'string',
        description: 'Working directory where command will execute',
      },
      execution_context: {
        type: 'string',
        enum: ['development', 'staging', 'production'],
        description: 'Deployment environment for context-aware analysis',
      },
      piped_from: {
        type: 'string',
        description: 'Previous command output being piped into this command',
      },
    },
    required: ['command'],
  },
  annotations: {
    title: 'Scan CLI Command',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
