/**
 * reset_session Tool
 * Resets the L9 session correlation state for the current MCP session.
 * Clears accumulated multi-turn attack tracking so subsequent benign
 * prompts are not penalized by prior session trajectory.
 */

import { config, getAuthHeaders, getSessionId, getAgentId } from '../config.js';

export interface SessionResetInput {
  reason?: string;
  session_id?: string;
  agent_id?: string;
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
  const sessionId = input.session_id || getSessionId();
  const agentId = input.agent_id || getAgentId();

  // Timeout guard: without an AbortController, fetch waits indefinitely
  // for the backend to respond. If the correlator mutex is held or the
  // backend is stuck, MCP clients (Claude Desktop, agents) hang forever
  // instead of surfacing an error the caller can react to. Use the same
  // timeout budget as scan operations for consistency.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

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
        signal: controller.signal,
      }
    );

    clearTimeout(timeoutId);

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
    clearTimeout(timeoutId);

    if (error instanceof Error && error.name === 'AbortError') {
      console.error(`Session reset timed out after ${config.scanTimeoutMs}ms`);
      return {
        success: false,
        session_id: sessionId,
        message: 'Session reset timed out',
        error: 'Request timed out',
      };
    }

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
      session_id: {
        type: 'string',
        description: 'Optional session identifier to reset. Defaults to the MCP server\'s current derived session ID.',
      },
      agent_id: {
        type: 'string',
        description: 'Optional agent identifier for the reset. Defaults to the MCP server\'s current derived agent ID.',
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
