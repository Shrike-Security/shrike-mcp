/**
 * scan_declare_scope Tool
 *
 * Declares (or replaces) the operating scope for an agent under the caller's
 * customer identity. Once a scope row exists for (customer_id, agent_id),
 * every subsequent scan call from that agent runs a pre-flight scope check
 * on the backend: tool calls outside allowed_tools (or explicitly on
 * forbidden_tools) route to refuse_tier: "require_approval" carrying a
 * scope_violation threat, and expired scopes emit scope_expired. Absent
 * a declaration, no scope check runs — every existing MCP integration
 * remains unaffected until it opts in.
 *
 * WHEN TO USE:
 *  - Agent bootstrapping — the client that starts a task-scoped agent
 *    declares the scope immediately so subsequent tool calls are policed.
 *  - Scope refresh — before an existing scope hits expires_at, the caller
 *    can re-declare with a new expires_at (upsert semantics).
 *  - Explicit tightening — after observing a misbehavior, tighten
 *    forbidden_tools without changing the rest of the scope.
 *
 * WHAT IT DOES NOT DO:
 *  - Does not scan content — scope declaration is metadata, not a scan.
 *  - Does not enforce inheritance for sub-agents (Tier 2).
 *  - Does not carry data_boundaries or blast_radius (Tier 2).
 *
 * ERROR HANDLING: Declaration failures should not crash the agent; the
 * caller can retry. Returning { error } lets the model surface the failure
 * to the human operator.
 */

import { config, getAuthHeaders } from '../config.js';

export interface ScanDeclareScopeInput {
  agent_id: string;
  purpose?: string;
  allowed_tools: string[];
  forbidden_tools?: string[];
  max_duration_seconds?: number;
  /** Action ceiling: scans passed under this scope before further actions are held for approval. Re-declaring resets the count. */
  max_actions?: number;
  expires_at?: string;
}

export interface ScanDeclareScopeResult {
  scope_id?: string;
  agent_id?: string;
  purpose?: string;
  allowed_tools?: string[];
  forbidden_tools?: string[];
  max_duration_seconds?: number;
  max_actions?: number;
  expires_at?: string;
  active_until?: string;
  expired?: boolean;
  created_at?: string;
  updated_at?: string;
  error?: string;
}

export async function scanDeclareScope(
  input: ScanDeclareScopeInput,
): Promise<ScanDeclareScopeResult> {
  if (!input || typeof input.agent_id !== 'string' || input.agent_id.trim() === '') {
    return { error: 'agent_id is required' };
  }
  if (!Array.isArray(input.allowed_tools)) {
    return { error: 'allowed_tools is required (use ["*"] to allow any tool)' };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    const url = `${config.backendUrl}/api/v1/agent/scope/declare`;
    const body: Record<string, unknown> = {
      agent_id: input.agent_id.trim(),
      allowed_tools: input.allowed_tools,
    };
    if (input.purpose) body.purpose = input.purpose;
    if (input.forbidden_tools) body.forbidden_tools = input.forbidden_tools;
    if (typeof input.max_duration_seconds === 'number') {
      body.max_duration_seconds = input.max_duration_seconds;
    }
    if (typeof input.max_actions === 'number') {
      body.max_actions = input.max_actions;
    }
    if (input.expires_at) body.expires_at = input.expires_at;

    const response = await fetch(url, {
      method: 'POST',
      headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      return {
        error: text.trim() || `Backend returned ${response.status}`,
      };
    }

    return (await response.json()) as ScanDeclareScopeResult;
  } catch (error) {
    clearTimeout(timeoutId);

    if (error instanceof Error && error.name === 'AbortError') {
      return { error: 'Request timed out' };
    }
    return {
      error: error instanceof Error ? error.message : 'Request failed',
    };
  }
}

/**
 * MCP Tool definition for scan_declare_scope
 */
export const scanDeclareScopeTool = {
  name: 'scan_declare_scope',
  description: `Declare (or refresh) the operating scope for a task-scoped agent under this customer's identity. Once declared, every subsequent scan call for this agent_id is enforced against the scope: tool calls outside allowed_tools — or explicitly on forbidden_tools — route to refuse_tier: "require_approval" with threat_type "scope_violation". Expired scopes emit "scope_expired". Absent a declaration, no scope check runs.

WHEN TO USE:
- At agent bootstrap for a task-scoped enterprise agent (invoice reconciliation, incident triage, etc.).
- Before expiry, to extend the scope with a fresh expires_at or max_duration_seconds (upsert).
- To tighten forbidden_tools after observing a policy-adjacent action.

INPUTS:
- agent_id (required): the identity you want scoped; same string you'll pass in context.agent_id on subsequent scan calls.
- allowed_tools (required): array of exact tool names. Use ["*"] to allow any tool.
  VOCABULARY: for actions scanned through this MCP server, the tool name is the scan CONTENT TYPE, not your framework's tool label — "command" (scan_command), "sql" (scan_sql_query), "file_path"/"file_content" (scan_file_write), "web_search", "a2a_message", "agent_card", "mcp_schema", "rag_context". Declaring names like "Bash" or "git" will NOT match; a scan_command call is checked as "command". Callers on the REST/SDK path can also set request_metadata.tool_name explicitly, and then THAT string is what must appear here.
- forbidden_tools (optional): array of tool names that this agent must never call; wins over allowed_tools. Same vocabulary as allowed_tools.
- purpose (optional): human-readable description, surfaces in dashboard + audit logs.
- max_duration_seconds (optional): TTL relative to created_at.
- max_actions (optional): action ceiling — how many scans this scope passes before further actions are held for approval with threat_type "resource_exhaustion". Re-declaring the scope resets the count. Counting is per backend instance, so treat the ceiling as a tripwire (it can overshoot slightly under horizontal scaling), not an exact meter.
- expires_at (optional, ISO-8601): absolute expiry; whichever bound fires first wins.

WHAT IT DOES NOT DO:
- Does not enforce delegation-chain inheritance for sub-agents (Tier 2).
- Does not carry data_boundaries or per-tool blast_radius (Tier 2).
- Does not scan content — declaration is metadata, not a scan.

ERROR HANDLING: Failures are non-blocking. The tool returns { error } so the agent can retry or surface the issue.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      agent_id: {
        type: 'string',
        description: 'Agent identifier this scope declares. Same string used in subsequent scan context.',
      },
      purpose: {
        type: 'string',
        description: 'Human-readable purpose for the scoped agent (audit + dashboard display).',
      },
      allowed_tools: {
        type: 'array',
        items: { type: 'string' },
        description: 'Exact tool names permitted, in scan content-type vocabulary ("command", "sql", "file_path", "file_content", "web_search", "a2a_message", "agent_card", "mcp_schema", "rag_context") — not framework tool labels. Use ["*"] for any tool.',
      },
      forbidden_tools: {
        type: 'array',
        items: { type: 'string' },
        description: 'Tool names explicitly forbidden. Wins over allowed_tools.',
      },
      max_duration_seconds: {
        type: 'integer',
        description: 'Optional TTL in seconds relative to created_at.',
      },
      max_actions: {
        type: 'integer',
        description: 'Optional action ceiling: scans passed under this scope before further actions are held for approval. Re-declaring resets the count.',
      },
      expires_at: {
        type: 'string',
        description: 'Optional absolute expiry (ISO-8601). Earlier of this and max_duration_seconds wins.',
      },
    },
    required: ['agent_id', 'allowed_tools'],
  },
  annotations: {
    title: 'Declare Agent Scope',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};
