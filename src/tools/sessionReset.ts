/**
 * reset_session Tool
 * Resets the L9 session correlation state for the current MCP session.
 * Clears accumulated multi-turn attack tracking so subsequent benign
 * prompts are not penalized by prior session trajectory.
 */

import { config, getAuthHeaders, getSessionId, getAgentId } from '../config.js';

export interface SessionResetInput {
  reason?: string;
}

export interface SessionResetResult {
  success: boolean;
  session_id: string;
  message: string;
  error?: string;
}

/**
 * Resets the session correlation state on the backend.
 */
export async function resetSession(input: SessionResetInput): Promise<SessionResetResult> {
  const sessionId = getSessionId();
  const agentId = getAgentId();

  try {
    const response = await fetch(
      `${config.backendUrl}/api/session/reset`,
      {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          session_id: sessionId,
          agent_id: agentId,
          reason: input.reason || 'User-initiated session reset',
        }),
      }
    );

    if (!response.ok) {
      return {
        success: false,
        session_id: sessionId,
        message: 'Session reset failed',
        error: `Backend returned ${response.status}`,
      };
    }

    const data = await response.json() as {
      success: boolean;
      session_id: string;
    };

    return {
      success: data.success,
      session_id: data.session_id || sessionId,
      message: data.success
        ? 'Session correlation state has been reset. Future scans will start with a clean session trajectory.'
        : 'Session was not found or already expired.',
    };
  } catch (error) {
    console.error(`Session reset failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return {
      success: false,
      session_id: sessionId,
      message: 'Session reset request failed',
      error: error instanceof Error ? error.message : 'Request failed',
    };
  }
}

/**
 * MCP Tool definition for reset_session
 */
export const resetSessionTool = {
  name: 'reset_session',
  description: `Resets the session-aware correlation engine (Layer 9) state for the current session.

WHEN TO USE:
- After resolving a flagged multi-turn attack pattern (e.g., topic_pivot false positive)
- When starting a new logical task within the same MCP session
- After a user confirms that flagged content was a false positive
- When session trajectory has accumulated risk from legitimate security testing

WHAT IT DOES:
- Clears the accumulated turn history and risk score for this session
- Future scans start with a clean session trajectory
- Does NOT affect other sessions or global threat patterns

IMPORTANT: This only resets the correlation state. Individual scan results are unaffected — a prompt injection will still be blocked regardless of session state.

ERROR HANDLING: If this tool fails, it is non-critical. Scanning continues normally. The session will eventually expire on its own (2 hour TTL).`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      reason: {
        type: 'string',
        description: 'Optional reason for the reset (logged for audit purposes)',
      },
    },
    required: [],
  },
  annotations: {
    title: 'Reset Session',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
