/**
 * MCP Server Configuration
 * Loads settings from environment variables with sensible defaults
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';

/**
 * Per-request context for HTTP transport.
 * Allows each Copilot/HTTP request to carry its own API key and tool filter
 * without modifying individual tool handler files.
 */
export interface RequestContext {
  apiKey: string | null;
  customerId: string | null;
  enabledTools: string[] | null;
}

/** AsyncLocalStorage for per-request context (HTTP mode). */
export const requestContext = new AsyncLocalStorage<RequestContext>();

export interface Config {
  /** Transport mode: 'stdio' (default) or 'http' */
  transport: 'stdio' | 'http';
  /** HTTP server port (used when transport is 'http') */
  port: number;
  /** Backend API URL for scan requests */
  backendUrl: string;
  /** Shrike API key for authenticated (paid tier) scans. Set dynamically by KeyRotationManager. */
  apiKey: string | null;
  /** Key provider: 'env' (default), 'file', 'vault', 'aws', 'gcp' */
  keyProvider: string;
  /** Key rotation poll interval in ms. Default 300000 (5 min). 0 = disabled. */
  keyPollIntervalMs: number;
  /** File path for 'file' key provider (K8s Secrets volume mount) */
  keyFile: string;
  /** Timeout for scan requests in milliseconds */
  scanTimeoutMs: number;
  /** Rate limit: requests per minute per API key */
  rateLimitPerMinute: number;
  /** Heartbeat interval in milliseconds */
  heartbeatIntervalMs: number;
  /** Enable debug logging */
  debug: boolean;
  /** Tool registration mode: 'all' (default), 'selective', or 'bundled' */
  mode: 'all' | 'selective' | 'bundled';
  /** Enabled tools (used when mode is 'selective'). Null means all. */
  enabledTools: string[] | null;
}

function getEnvOrDefault(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

function getEnvNumber(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

export const config: Config = {
  transport: (process.env.MCP_TRANSPORT === 'http' ? 'http' : 'stdio') as 'stdio' | 'http',
  port: getEnvNumber('MCP_PORT', 8000),
  // Default uses load balancer for scalability. Override with SHRIKE_BACKEND_URL for VPC deployments.
  backendUrl: getEnvOrDefault('SHRIKE_BACKEND_URL', 'https://api.shrikesecurity.com/agent'),
  // API key — set dynamically by KeyRotationManager at startup.
  // For backwards compatibility, falls back to SHRIKE_API_KEY env var when keyProvider is 'env' (default).
  // Without API key, scans run the free tier: L1-L5 deterministic layers only
  // Get your API key at: https://console.shrikesecurity.com/api-keys
  apiKey: null as string | null,
  // Key provider: env (default), file, vault, aws, gcp
  // See docs for configuration per provider
  keyProvider: getEnvOrDefault('SHRIKE_KEY_PROVIDER', 'env'),
  keyPollIntervalMs: getEnvNumber('SHRIKE_KEY_POLL_INTERVAL_MS', 300000),
  keyFile: getEnvOrDefault('SHRIKE_KEY_FILE', '/var/run/secrets/shrike/api-key'),
  // SECURITY: 15000ms allows for full 8-layer scan pipeline with LLM analysis
  // Backend takes ~10s for comprehensive scans including vector embeddings + LLM
  scanTimeoutMs: getEnvNumber('MCP_SCAN_TIMEOUT_MS', 15000),
  rateLimitPerMinute: getEnvNumber('MCP_RATE_LIMIT_PER_MINUTE', 100),
  heartbeatIntervalMs: getEnvNumber('MCP_HEARTBEAT_INTERVAL_MS', 30000),
  debug: getEnvOrDefault('MCP_DEBUG', 'false') === 'true',
  // Tool selection: SHRIKE_MODE=bundled → single shrike_scan tool
  //                 SHRIKE_TOOLS=scan_prompt,scan_sql_query → selective mode
  //                 Neither set → all 7 tools (backwards compatible)
  mode: (() => {
    if (process.env.SHRIKE_MODE?.toLowerCase() === 'bundled') return 'bundled' as const;
    if (process.env.SHRIKE_TOOLS) return 'selective' as const;
    return 'all' as const;
  })(),
  enabledTools: process.env.SHRIKE_TOOLS
    ? process.env.SHRIKE_TOOLS.split(',').map(t => t.trim()).filter(Boolean)
    : null,
};

export function logConfig(): void {
  // Use stderr to avoid interfering with MCP JSON-RPC protocol on stdout
  console.error('MCP Server Configuration:');
  console.error(`  Transport: ${config.transport}`);
  console.error(`  Port: ${config.port} ${config.transport === 'stdio' ? '(unused in stdio mode)' : ''}`);
  console.error(`  Backend URL: ${config.backendUrl}`);
  console.error(`  Key Provider: ${config.keyProvider}`);
  // Key providers resolve asynchronously after this banner prints, so a
  // configured-but-not-yet-loaded key must not be reported as NOT SET.
  const keyStatus = config.apiKey
    ? `***${config.apiKey.slice(-4)} (authenticated - full pipeline)`
    : config.keyProvider === 'env'
      ? (process.env.SHRIKE_API_KEY
          ? `***${process.env.SHRIKE_API_KEY.slice(-4)} (validating at startup)`
          : 'NOT SET (free tier: L1-L5 pattern layers)')
      : `loading from ${config.keyProvider} provider (validated at startup)`;
  console.error(`  API Key: ${keyStatus}`);
  console.error(`  Key Poll Interval: ${config.keyPollIntervalMs}ms${config.keyPollIntervalMs === 0 ? ' (disabled)' : ''}`);
  console.error(`  Scan Timeout: ${config.scanTimeoutMs}ms`);
  console.error(`  Rate Limit: ${config.rateLimitPerMinute} req/min`);
  console.error(`  Mode: ${config.mode}`);
  console.error(`  Enabled Tools: ${config.enabledTools ? config.enabledTools.join(', ') : 'all'}`);
  console.error(`  Debug: ${config.debug}`);
}

/**
 * Returns authorization headers for backend requests.
 * In HTTP mode, per-request key from AsyncLocalStorage takes priority
 * over the process-level SHRIKE_API_KEY. This lets each Copilot user
 * send their own API key without modifying tool handler files.
 */
export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    // Channel tag for adoption analytics: the backend records this as
    // traffic_source so the dashboard can break scans down by integration
    // (MCP vs SDK vs gateway). Server-side resolveTrafficSource reads this
    // header; without it every scan falls back to the generic "api" bucket.
    'X-Traffic-Source': 'mcp',
  };
  const ctx = requestContext.getStore();
  const key = ctx?.apiKey ?? config.apiKey;
  if (key) {
    headers['Authorization'] = `Bearer ${key}`;
  }
  return headers;
}

/**
 * Session identity for this MCP server process.
 *
 * SESSION_ID is the client's fallback used when the caller does NOT supply
 * an explicit session_id on the tool call — caller-supplied values always
 * win. Auto-rotation (see rotateSessionIfTriggered)
 * only affects THIS fallback; it does not touch caller-managed session ids.
 *
 * AGENT_ID stays stable across rotations by design. Rotation is a
 * conversation-boundary reset, not an identity reset — the correlator needs
 * agent_id continuity to detect "same agent, N rapid rotations, keeps
 * hitting session_locked" as an attacker rate-limit signal. Erasing
 * agent_id on rotation would kill that observability.
 */
let SESSION_ID: string = randomUUID();
const AGENT_ID = process.env.SHRIKE_AGENT_ID || `mcp-${randomUUID().slice(0, 8)}`;

/** Returns the current session ID for this MCP server process (rotates automatically on quarantine / high-risk). */
export function getSessionId(): string {
  return SESSION_ID;
}

/** Returns the agent ID (from SHRIKE_AGENT_ID env or auto-generated). Stable across session rotations. */
export function getAgentId(): string {
  return AGENT_ID;
}

// ---------------------------------------------------------------------------
// Automatic session rotation on quarantine / high-risk
// ---------------------------------------------------------------------------
//
// When a scan response comes back with a session_locked verdict OR a
// session_state.session_risk_score above SHRIKE_ROTATION_THRESHOLD, the
// client generates a fresh SESSION_ID for subsequent calls that don't
// supply their own session_id. The rotated flag is surfaced back to the
// caller on the response that triggered it, so the agent can explain to
// its user why the session reset.
//
// Two triggers, orthogonal:
//   1. Verdict-based (SHRIKE_ROTATE_ON_LOCK, default "true"). Rotates when
//      response.threat_type === "session_locked". This is the safety net —
//      the correlator has already crossed 0.8 by then.
//   2. Score-based (SHRIKE_ROTATION_THRESHOLD, default 0.7). Rotates when
//      response.session_state.session_risk_score >= threshold. This is the
//      customer knob for "auto-rotate at score X." Set the env var to a
//      value > 1.0 (e.g. "2") to disable this trigger entirely.
//
// Neither trigger overrides caller-supplied session_id on the tool call.
// Rotation only shifts the client's fallback; if a caller manages their own
// session_id, they get the rotation reason on the response and can decide
// what to do on their end. See the active guidance layer +
// the symmetric-contract principle.

const ROTATE_ON_LOCK: boolean = process.env.SHRIKE_ROTATE_ON_LOCK !== 'false';
const ROTATION_THRESHOLD: number = (() => {
  const raw = process.env.SHRIKE_ROTATION_THRESHOLD;
  if (raw === undefined || raw === '') return 0.7;
  const parsed = parseFloat(raw);
  if (Number.isNaN(parsed)) return 0.7;
  return parsed;
})();

/**
 * Rotation record when the MCP client's fallback SESSION_ID was the one
 * used by the request (caller did not supply session_id on tool args).
 * MCP mutates its own SESSION_ID and reports previous → new.
 */
export interface ModuleOwnedRotation {
  rotated: true;
  /** Who owns the session lifecycle. `mcp_client` = MCP's fallback SESSION_ID rotated in place. */
  owner: 'mcp_client';
  /** Why the client rotated — "session_locked" verdict, or configured risk-score threshold crossed. */
  reason: 'session_locked' | 'risk_threshold_exceeded';
  /** The MCP fallback session_id that was in force before this rotation. */
  previous_session_id: string;
  /** The fresh session_id the MCP client will now use on subsequent calls that don't supply their own. */
  new_session_id: string;
  /** For "risk_threshold_exceeded", the score that crossed. For "session_locked", the score if the response carried one. */
  triggering_risk_score?: number;
  /** The threshold in force at the time of rotation (the constant matters for reproducibility). */
  configured_threshold?: number;
}

/**
 * Rotation recommendation when the CALLER supplied their own session_id
 * on the tool call — they own session lifecycle, so MCP can only signal.
 * `rotated: false` + `rotation_recommended: true` are the discriminant.
 * MCP does NOT mutate its module SESSION_ID in this branch. The caller
 * decides whether to adopt `suggested_new_session_id`, mint their own,
 * or ignore the recommendation.
 *
 * Per-event suggestion contract: `suggested_new_session_id` is minted
 * per recommendation and is NOT a stable "next id" the caller should
 * cache across turns. If the caller ignores turn N's suggestion and
 * stays on `current_session_id`, turn N+1 will emit a fresh
 * recommendation with a different `suggested_new_session_id`. Callers
 * that persist and re-use a stale suggestion will find it de-correlated
 * from the event that produced it. Adopt the suggestion at the moment
 * of the recommendation, or ignore it and let the next event mint its
 * own — do not cache-key on the value.
 */
export interface CallerOwnedRotationRecommendation {
  rotated: false;
  rotation_recommended: true;
  /** Who owns the session lifecycle. `caller` = the tool caller supplied session_id. */
  owner: 'caller';
  /** Why MCP is recommending rotation. Same semantics as ModuleOwnedRotation.reason. */
  reason: 'session_locked' | 'risk_threshold_exceeded';
  /** The session_id the caller supplied on this tool call, echoed back so integrators can correlate. */
  current_session_id: string;
  /**
   * A fresh UUID MCP suggests the caller adopt for subsequent calls.
   * Advisory. Per-event, not a stable next-id — see interface docstring.
   */
  suggested_new_session_id: string;
  triggering_risk_score?: number;
  configured_threshold?: number;
}

/**
 * Rotation record surfaced back to the caller on the response that
 * triggered a rotation (module-owned) or a rotation recommendation
 * (caller-owned). Discriminated union on `rotated`.
 */
export type SessionRotation = ModuleOwnedRotation | CallerOwnedRotationRecommendation;

/**
 * Shape the rotation helper needs to see. Subset of the sanitized response
 * types (SanitizedBlockedResponse | SanitizedAllowedResponse | SanitizedApprovalResponse)
 * — kept structurally light here to avoid a circular dependency between
 * config.ts and responseFormatter.ts (which imports config for getSessionId).
 *
 * effective_session_id is the id that was actually sent to the backend for
 * this scan. When it matches the current module SESSION_ID, MCP owns the
 * session and rotation is performative. When it differs, the caller owns
 * the session and rotation is a recommendation, not a mutation.
 */
export interface RotationTriggerInput {
  threat_type?: string;
  session_state?: {
    session_risk_score: number;
    session_turn_number: number;
    session_patterns: string[];
  };
  effective_session_id: string;
}

/**
 * Inspects a scan response, rotates SESSION_ID (module-owned case) or
 * emits a recommendation (caller-owned case), and returns a SessionRotation
 * record describing what happened. Returns null when no trigger fired.
 * Callers should attach the return value to the response as
 * `client_session_rotation` when non-null.
 *
 * Ownership detection: if `effective_session_id === SESSION_ID`, the MCP
 * client's fallback was used → module-owned; else the caller supplied their
 * own → caller-owned (no mutation, recommendation only).
 *
 * Deterministic ordering: verdict-based check first (safety net), then
 * score-based. If both would fire on the same response, verdict wins for
 * the reason label — it's the more specific cause.
 */
export function rotateSessionIfTriggered(input: RotationTriggerInput): SessionRotation | null {
  let reason: SessionRotation['reason'] | null = null;

  if (ROTATE_ON_LOCK && input.threat_type === 'session_locked') {
    reason = 'session_locked';
  } else if (
    ROTATION_THRESHOLD <= 1.0 &&
    input.session_state &&
    input.session_state.session_risk_score >= ROTATION_THRESHOLD
  ) {
    reason = 'risk_threshold_exceeded';
  }

  if (!reason) return null;

  const isCallerOwned = input.effective_session_id !== SESSION_ID;

  if (isCallerOwned) {
    const rec: CallerOwnedRotationRecommendation = {
      rotated: false,
      rotation_recommended: true,
      owner: 'caller',
      reason,
      current_session_id: input.effective_session_id,
      suggested_new_session_id: randomUUID(),
      configured_threshold: ROTATION_THRESHOLD,
    };
    if (input.session_state) {
      rec.triggering_risk_score = input.session_state.session_risk_score;
    }
    console.error(
      `[session-rotation] owner=caller reason=${reason} current=${input.effective_session_id.slice(0, 8)}... suggested=${rec.suggested_new_session_id.slice(0, 8)}... score=${input.session_state?.session_risk_score ?? 'n/a'} threshold=${ROTATION_THRESHOLD}`,
    );
    return rec;
  }

  const previous = SESSION_ID;
  SESSION_ID = randomUUID();

  const rotation: ModuleOwnedRotation = {
    rotated: true,
    owner: 'mcp_client',
    reason,
    previous_session_id: previous,
    new_session_id: SESSION_ID,
    configured_threshold: ROTATION_THRESHOLD,
  };
  if (input.session_state) {
    rotation.triggering_risk_score = input.session_state.session_risk_score;
  }

  console.error(
    `[session-rotation] owner=mcp_client reason=${reason} previous=${previous.slice(0, 8)}... new=${SESSION_ID.slice(0, 8)}... score=${input.session_state?.session_risk_score ?? 'n/a'} threshold=${ROTATION_THRESHOLD}`,
  );

  return rotation;
}

/**
 * Test-only helper. Resets the process-level SESSION_ID to a known value so
 * unit tests can assert rotation-before/after without relying on global
 * process state ordering. Not part of the public MCP contract.
 */
export function __resetSessionIdForTesting(newId: string): void {
  SESSION_ID = newId;
}

/** All valid tool names that can be used with SHRIKE_TOOLS */
export const VALID_TOOL_NAMES = [
  'scan_prompt', 'scan_response', 'scan_sql_query', 'scan_command',
  'scan_file_write', 'scan_web_search', 'report_bypass',
  'check_approval', 'reset_session', 'session_status',
  'scan_a2a_message', 'scan_agent_card',
  // Scope Tier 1 — declared agent scope surface. See the agent-scope declaration design.
  'scan_declare_scope',
  // §9.2 tool-poisoning close-out — one-shot scan of a single MCP tool
  // description/inputSchema. Complements the MCPGateway proxy path which
  // scans every tools/list automatically. See docs/post-launch-roadmap-2026-07.md §9.2.
  'scan_mcp_schema',
] as const;

export type ValidToolName = typeof VALID_TOOL_NAMES[number];
