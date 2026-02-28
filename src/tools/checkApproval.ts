/**
 * check_approval Tool
 * Checks the status of a pending approval or submits a decision.
 *
 * Two modes:
 *   - Poll mode: approval_id only → GET /api/v1/approvals/{id}/status
 *   - Decide mode: approval_id + decision + justification → POST /api/v1/approvals/{id}/decide
 *
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance.
 */

import { config, getAuthHeaders } from '../config.js';
import { generateRequestId, type SanitizedResponse } from '../utils/responseFormatter.js';

export interface CheckApprovalInput {
  approval_id: string;
  decision?: 'approved' | 'rejected';
  justification?: string;
}

interface ApprovalStatusResponse {
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'cancelled';
  // SHRIKE-302: Backend returns expires_in_seconds (precomputed), not expires_at
  expires_in_seconds?: number;
  decided_by?: string;
  decided_at?: string;
  decided_via?: string;
  justification?: string;
}

/**
 * Checks approval status or submits a decision.
 *
 * @param input - The approval check/decide parameters
 * @param customerId - Customer identifier for logging
 * @returns Sanitized response with approval status
 */
export async function checkApproval(input: CheckApprovalInput, customerId: string = 'anonymous'): Promise<SanitizedResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    if (input.decision) {
      // Decide mode: POST /api/v1/approvals/{id}/decide
      const response = await fetch(`${config.backendUrl}/api/v1/approvals/${encodeURIComponent(input.approval_id)}/decide`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          decision: input.decision,
          justification: input.justification || '',
          decided_by: customerId,
          decided_via: 'mcp',
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // SHRIKE-401: Handle severity-based enforcement responses
        if (response.status === 403) {
          const errorData = await response.json().catch(() => ({ error: 'Forbidden', code: 'UNKNOWN' }));
          const code = errorData.code || '';
          console.error(`[check_approval] Decision blocked: ${response.status} code=${code} ${errorData.error}`);

          if (code === 'DASHBOARD_REQUIRED') {
            return buildDashboardRequiredResponse(requestId, errorData.error);
          }
          if (code === 'COOLDOWN_ACTIVE') {
            return buildCooldownResponse(requestId, errorData.error);
          }
          if (code === 'SELF_APPROVAL_BLOCKED') {
            return buildSelfApprovalBlockedResponse(requestId);
          }
          if (code === 'SCANNER_ROUTE_DENIED') {
            return buildDashboardRequiredResponse(requestId, errorData.error);
          }
          return buildErrorResponse(requestId, errorData.error || 'Forbidden');
        }

        const errorText = await response.text().catch(() => 'Unknown error');
        console.error(`[check_approval] Decision failed: ${response.status} ${errorText}`);
        return buildErrorResponse(requestId, `Failed to submit decision: ${response.status}`);
      }

      const scanTimeMs = Date.now() - startTime;
      console.error(`[check_approval] ${requestId} decision=${input.decision} approval_id=${input.approval_id} time=${scanTimeMs}ms`);

      // SHRIKE-301: Rejection must return blocked:true so agents stop
      if (input.decision === 'rejected') {
        return {
          blocked: true,
          action: 'block',
          threat_type: 'unknown' as any,
          owasp_category: 'N/A',
          severity: 'medium' as any,
          confidence: 'high' as any,
          guidance: `Action rejected.${input.justification ? ` Reason: ${input.justification}` : ''}`,
          agent_instruction: 'The approval has been REJECTED. Do NOT proceed with the original action. Inform the user of the rejection.',
          user_message: `The action was rejected by a reviewer.${input.justification ? ` Reason: ${input.justification}` : ' Contact your security team for details.'}`,
          audit: {
            scan_id: requestId,
            timestamp: new Date().toISOString(),
          },
          request_id: requestId,
        };
      }

      return {
        blocked: false,
        action: 'allow',
        agent_instruction: 'The approval has been APPROVED. You may now proceed with the original action that was held for approval.',
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };
    }

    // Poll mode: GET /api/v1/approvals/{id}/status
    const response = await fetch(`${config.backendUrl}/api/v1/approvals/${encodeURIComponent(input.approval_id)}/status`, {
      method: 'GET',
      headers: getAuthHeaders(),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      console.error(`[check_approval] Status check failed: ${response.status} ${errorText}`);
      return buildErrorResponse(requestId, `Failed to check approval status: ${response.status}`);
    }

    const data = await response.json() as ApprovalStatusResponse;
    const scanTimeMs = Date.now() - startTime;

    console.error(`[check_approval] ${requestId} status=${data.status} approval_id=${input.approval_id} time=${scanTimeMs}ms`);

    return buildStatusResponse(data, requestId);

  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof Error && error.name === 'AbortError') {
      console.error(`[check_approval] Timed out after ${config.scanTimeoutMs}ms`);
      return buildErrorResponse(requestId, 'Request timed out');
    }

    console.error(`[check_approval] Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return buildErrorResponse(requestId, 'Failed to check approval status');
  }
}

/**
 * Builds a status response based on approval state.
 */
function buildStatusResponse(data: ApprovalStatusResponse, requestId: string): SanitizedResponse {
  // SHRIKE-302: Backend returns precomputed expires_in_seconds, not expires_at
  const expiresInSeconds = data.expires_in_seconds ?? 0;

  switch (data.status) {
    case 'approved':
      return {
        blocked: false,
        action: 'allow',
        agent_instruction: 'This action has been APPROVED by a human reviewer. You may now proceed with the original action that was held for approval.',
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };

    case 'rejected':
      return {
        blocked: true,
        action: 'block',
        threat_type: 'unknown',
        owasp_category: 'N/A',
        severity: 'medium',
        confidence: 'high',
        guidance: `This action was rejected by a human reviewer.${data.justification ? ` Reason: ${data.justification}` : ''}`,
        agent_instruction: 'This action has been REJECTED by a human reviewer. Do NOT proceed with the original action. Inform the user that the action was denied and provide the rejection reason if available.',
        user_message: `Your requested action was reviewed and rejected.${data.justification ? ` Reason: ${data.justification}` : ' Contact your security team for details.'}`,
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };

    case 'expired':
      return {
        blocked: true,
        action: 'block',
        threat_type: 'unknown',
        owasp_category: 'N/A',
        severity: 'low',
        confidence: 'high',
        guidance: 'The approval request expired before a decision was made.',
        agent_instruction: 'This approval has EXPIRED without a decision. Do NOT proceed with the original action. Inform the user that the approval timed out and they may need to re-initiate the action.',
        user_message: 'The approval request has expired. Please re-initiate the action if you still need it.',
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };

    case 'cancelled':
      return {
        blocked: true,
        action: 'block',
        threat_type: 'unknown',
        owasp_category: 'N/A',
        severity: 'low',
        confidence: 'high',
        guidance: 'The approval request was cancelled.',
        agent_instruction: 'This approval has been CANCELLED. Do NOT proceed with the original action. Inform the user that the approval was cancelled.',
        user_message: 'The approval request has been cancelled.',
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };

    case 'pending':
    default: {
      const minutesLeft = Math.ceil(expiresInSeconds / 60);
      return {
        blocked: true,
        action: 'require_approval',
        approval_id: data.id,
        approval_context: {
          action_summary: (data as any).action_summary || 'Awaiting human approval',
          policy_name: (data as any).policy_name || 'Approval Policy',
          approval_level: (data as any).approval_level || 'edge',
          expires_in_seconds: expiresInSeconds,
        },
        agent_instruction: `This approval is still PENDING (expires in ${minutesLeft} minutes). Do NOT proceed with the original action. Do NOT poll in a loop. Inform the user that the approval is still awaiting a decision and wait for them to ask you to check again.`,
        user_message: `Approval is still pending. It will expire in ${minutesLeft} minutes if not reviewed.`,
        audit: {
          scan_id: requestId,
          timestamp: new Date().toISOString(),
        },
        request_id: requestId,
      };
    }
  }
}

/**
 * Builds an error response for failed approval checks.
 */
function buildErrorResponse(requestId: string, reason: string): SanitizedResponse {
  return {
    blocked: true,
    action: 'block',
    threat_type: 'scan_error',
    owasp_category: 'N/A',
    severity: 'medium',
    confidence: 'high',
    guidance: reason,
    agent_instruction: `Could not check approval status: ${reason}. Do NOT proceed with the original action without a confirmed approval. Inform the user of the error.`,
    user_message: `Unable to check approval status: ${reason}. Please try again or contact your administrator.`,
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
    },
    request_id: requestId,
  };
}

/**
 * SHRIKE-401: Response for high/critical approvals that require dashboard auth.
 */
function buildDashboardRequiredResponse(requestId: string, serverMsg: string): SanitizedResponse {
  return {
    blocked: true,
    action: 'block',
    threat_type: 'scan_error',
    owasp_category: 'LLM08',
    severity: 'high',
    confidence: 'high',
    guidance: serverMsg,
    agent_instruction: 'This approval requires dashboard authentication. You CANNOT approve or reject it from here. Direct the user to the Shrike Security dashboard to review and decide on this approval.',
    user_message: 'This approval must be decided through the Shrike Security dashboard. Please log in to your dashboard to approve or reject this action.',
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
    },
    request_id: requestId,
  };
}

/**
 * SHRIKE-401: Response when cooldown period hasn't elapsed yet.
 */
function buildCooldownResponse(requestId: string, serverMsg: string): SanitizedResponse {
  return {
    blocked: true,
    action: 'block',
    threat_type: 'scan_error',
    owasp_category: 'LLM08',
    severity: 'medium',
    confidence: 'high',
    guidance: serverMsg,
    agent_instruction: 'The approval is in a mandatory review cooldown period. Wait for the cooldown to expire, then ask the user if they want you to try submitting the decision again.',
    user_message: `${serverMsg}. This cooldown ensures time for human review before any decision is accepted.`,
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
    },
    request_id: requestId,
  };
}

/**
 * SHRIKE-401: Response when the same user tries to approve their own request.
 */
function buildSelfApprovalBlockedResponse(requestId: string): SanitizedResponse {
  return {
    blocked: true,
    action: 'block',
    threat_type: 'scan_error',
    owasp_category: 'LLM08',
    severity: 'high',
    confidence: 'high',
    guidance: 'Self-approval is not permitted. A different authorized user must review and decide on this approval.',
    agent_instruction: 'Self-approval was blocked by the server. The user who triggered this scan cannot approve their own request. A different authorized user must decide. Inform the user of this requirement.',
    user_message: 'Self-approval is not permitted. A different authorized user must review and decide on this approval through the Shrike dashboard.',
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
    },
    request_id: requestId,
  };
}

/**
 * MCP Tool definition for check_approval
 */
export const checkApprovalTool = {
  name: 'check_approval',
  description: `Check the status of a pending approval, or submit a decision.

WHEN TO USE: Only when the user asks you to check an approval or when you need to verify approval status before proceeding with a previously held action.

POLL MODE (no decision parameter): Returns the current status of an approval.
- status="pending": approval is still awaiting a human decision. Inform the user it is still pending and STOP. Do NOT poll in a loop — wait for the user to ask you to check again.
- status="approved": the action has been approved. You may now proceed with the original action that was held.
- status="rejected": the action was denied. Return the rejection reason to the user and STOP. Do not retry.
- status="expired": the approval timed out without a decision. Inform the user and STOP.

DECIDE MODE (decision + justification parameters): Submits a decision after the user explicitly instructs you to approve or reject.
- You MUST present the full approval context (threat type, severity, risk factors) to the user FIRST.
- You MUST wait for the user's EXPLICIT instruction (e.g., "approve it", "reject it") before calling with a decision.
- NEVER decide autonomously — always require explicit human instruction.
- High/critical severity approvals can ONLY be decided via the Shrike dashboard — the server will reject MCP-submitted decisions for these.
- Low/medium severity approvals have a 60-second cooldown after creation before decisions are accepted.
- If the server returns a 403 error, inform the user of the reason and direct them to the dashboard if needed.

IMPORTANT: Do NOT automatically poll in a loop. Approvals may take minutes to hours. Inform the user of the pending status and wait for them to ask you to check again.

Enterprise context: Provides the human-in-the-loop control required for compliance (GDPR Art. 22, SOC2 CC8.1). Every decision is recorded with full audit trail.

ERROR HANDLING: If this tool returns an error, inform the user. Do NOT proceed with the original action without a confirmed approval.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      approval_id: {
        type: 'string',
        description: 'The approval ID returned by a scan tool when action was require_approval',
      },
      decision: {
        type: 'string',
        enum: ['approved', 'rejected'],
        description: 'Submit a decision ONLY after the user explicitly instructs you to approve or reject. Never decide autonomously.',
      },
      justification: {
        type: 'string',
        description: 'Reason for the decision (recommended for rejections)',
      },
    },
    required: ['approval_id'],
  },
  annotations: {
    title: 'Check Approval',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
