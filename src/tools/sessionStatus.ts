/**
 * session_status Tool
 *
 * Read-only lookup of the current L9 session's correlation state. Anti-thesis
 * of reset_session: never mutates, never touches turn count or expiry. The
 * canonical Recovery block emitted on session_locked verdicts
 * lists this tool in `available_tools`, promising that a locked-session
 * caller can still call it — so this must remain callable inside quarantine.
 *
 * WHEN TO USE:
 * - After a verdict returned refuse_tier: "block" with threat_type
 *   "session_locked" — call this to confirm the risk score and
 *   session_locked flag before rotating to a fresh session_id.
 * - Before deciding whether to rotate proactively — check if session risk
 *   has crossed the "warn" threshold (0.7).
 * - When integrating a new agent and wanting to observe accumulated L9
 *   state without triggering another scan.
 *
 * WHAT IT DOES NOT DO:
 * - Does not clear or modify session state (use reset_session for that).
 * - Does not scan content or update the turn counter.
 * - Does not expose per-turn content, detector confidences, or delegation
 *   internals.
 */

import { config, getAuthHeaders, getSessionId, getAgentId } from '../config.js';

export interface SessionStatusInput {
  session_id?: string;
  agent_id?: string;
}

export interface SessionStatusRecovery {
  instruction: string;
  available_tools?: string[];
  patterns_triggered?: string[];
}

export interface SessionStatusResult {
  exists: boolean;
  session_id: string;
  agent_id: string;
  session_risk_score?: number;
  session_turn_number?: number;
  session_locked?: boolean;
  refuse_tier?: 'allow' | 'warn' | 'block';
  session_patterns?: string[];
  first_scan_at?: string;
  last_scan_at?: string;
  expires_at?: string;
  recovery?: SessionStatusRecovery;
  error?: string;
}

/**
 * Fetches the current L9 session status from the backend.
 */
export async function sessionStatus(input: SessionStatusInput): Promise<SessionStatusResult> {
  const sessionId = input.session_id || getSessionId();
  const agentId = input.agent_id || getAgentId();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    const url = new URL(`${config.backendUrl}/api/session/status`);
    url.searchParams.set('session_id', sessionId);
    url.searchParams.set('agent_id', agentId);

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: getAuthHeaders(),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        exists: false,
        session_id: sessionId,
        agent_id: agentId,
        error: `Backend returned ${response.status}`,
      };
    }

    const data = await response.json() as SessionStatusResult;
    // Backend always echoes session_id + agent_id; forward as-is. If the
    // backend returned exists=false, the additional fields will be absent
    // and the caller's type-narrowing must respect that.
    return data;
  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof Error && error.name === 'AbortError') {
      return {
        exists: false,
        session_id: sessionId,
        agent_id: agentId,
        error: 'Request timed out',
      };
    }

    return {
      exists: false,
      session_id: sessionId,
      agent_id: agentId,
      error: error instanceof Error ? error.message : 'Request failed',
    };
  }
}

/**
 * MCP Tool definition for session_status
 */
export const sessionStatusTool = {
  name: 'session_status',
  description: `Read-only status of the current L9 session's correlation state.

WHEN TO USE:
- After Shrike returns refuse_tier: "block" with threat_type "session_locked" — confirm the risk score and locked flag before rotating to a new session_id.
- To observe accumulated session risk before deciding whether to proactively rotate.
- To surface the current session_patterns to the user for context.

WHAT IT RETURNS:
- exists: whether the L9 correlator has cached state for this session
- session_risk_score (0.0–1.0, 2dp), session_turn_number
- session_locked: true when risk >= 0.8 (next scan will short-circuit)
- refuse_tier: "block" (>= 0.8), "warn" (>= 0.7), or "allow" (< 0.7)
- session_patterns: canonical multi_turn_* strings when anomaly-gated (risk >= 0.5); empty otherwise
- recovery: canonical rotate-and-restart guidance, only when session_locked

WHAT IT DOES NOT DO:
- Does not modify session state — use reset_session to clear low-risk state, or contact the platform admin for high-risk sessions.
- Does not expose per-turn content, detector confidences, or agent delegation internals.

ERROR HANDLING: Non-critical. If this tool fails, the caller can still rotate the session_id manually — that is always safe.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      session_id: {
        type: 'string',
        description: 'Optional session identifier. Defaults to the MCP server\'s current derived session ID.',
      },
      agent_id: {
        type: 'string',
        description: 'Optional agent identifier. Defaults to the MCP server\'s current derived agent ID.',
      },
    },
    required: [],
  },
  annotations: {
    title: 'Session Status',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
