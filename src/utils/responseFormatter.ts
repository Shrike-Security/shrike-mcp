/**
 * Response Formatter for IP Protection
 *
 * Sanitizes MCP server responses to protect Shrike's intellectual property
 * by removing internal detection layer details while preserving actionable
 * guidance for users.
 *
 * Internal details are logged to stderr for debugging (not exposed to clients).
 */

import { rotateSessionIfTriggered } from '../config.js';

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Threat types exposed to external clients (normalized from internal types)
 */
export type ThreatType =
  | 'prompt_injection'
  | 'jailbreak'
  | 'system_prompt_leak'
  | 'data_exfiltration'
  | 'sql_injection'
  | 'path_traversal'
  | 'secrets_exposure'
  | 'pii_exposure'
  | 'blocked_domain'
  | 'toxic_content'
  | 'toxicity' // legacy alias for toxic_content, kept for back-compat
  | 'multi_turn_attack' // L9 pseudo-category — any multi_turn_* pattern
  | 'session_locked' // Session-quarantine short-circuit (accumulated L9 risk >= 0.8)
  | 'malicious_code'
  | 'harmful_intent'
  | 'social_engineering'
  | 'privilege_escalation'
  | 'destructive_operation'
  | 'scan_error'
  | 'size_limit_exceeded'
  | 'unknown';

/**
 * Confidence bucket levels (replaces raw 0.0-1.0 scores)
 */
export type ConfidenceBucket = 'high' | 'medium' | 'low';

/**
 * Severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Correlation pattern detail from L9 session-aware correlation engine.
 * Retained for backwards compatibility of the (now unused) audit block hook;
 * new integrators should read the top-level `session_state.session_patterns`
 * array of canonical threat_type strings instead.
 */
export interface CorrelationPattern {
  pattern_id: string;
  pattern_name: string;
  category: string;
  confidence: number;
  description: string;
}

/**
 * SessionState is the agent-visible L9 session outcome contract carried
 * top-level on every sanitized scan response — observe-plane and act-plane,
 * allowed and blocked — whenever the caller supplies a session_id or
 * agent_id. The block lets integrators build governance policies on top
 * of Shrike (auto-rotate above a risk threshold, escalate at turn N,
 * cross-agent supervision) without depending on tool-specific side-channels.
 *
 * Distinct from the internal L9 correlation metrics: those carry pattern
 * names, per-detector confidences, and layer timings, and stay on the
 * backend's dashboard surface. This block is designed from the start to
 * be safe for agents to consume — outputs, not inputs, of the L9 decision.
 *
 * See the symmetric-contract principle (why the block is symmetric —
 * present on every response, not only blocks) and the dashboard IP boundary
 * (the outcome-vs-attribution split).
 */
export interface SessionState {
  /** 0.0-1.0, rounded to 2 decimal places. */
  session_risk_score: number;
  /** 1-indexed within the session. */
  session_turn_number: number;
  /**
   * Canonical multi_turn_* threat-type strings (empty array, not omitted,
   * when no patterns matched). Uses the same taxonomy already surfaced
   * on `violations[].threat_type` in a block response.
   */
  session_patterns: string[];
  /**
   * Attribution of session_risk_score to the individual L9 signals that
   * drove it. Lets a policy-tuner or "why blocked?" surface see which
   * components pushed the score up, without exposing detector internals.
   * Empty array (not omitted) when no signals contributed. Present when
   * the backend supports the field; older backends may omit — treat
   * absence as empty. See models.RiskBreakdown (backend).
   */
  risk_breakdown?: RiskBreakdown[];
  /**
   * True when accumulated L9 risk crossed the lock threshold (>= 0.8) and
   * the session is under quarantine. Callers gate retry / rotation logic
   * on this signal. Absent (undefined) is treated as false — omit when the
   * backend did not report a lock state (older backends).
   */
  session_locked?: boolean;
}

/**
 * One line-item in SessionState.risk_breakdown — attribution of a single
 * L9 signal's contribution to the session risk score.
 * See models.RiskBreakdown (backend Go type) for the canonical contract.
 */
export interface RiskBreakdown {
  /** Coarse category: "pattern" | "turn_content" | "trajectory" | "turn_metrics" | "carried_session_risk" | "signal" (fallback). */
  source: string;
  /** Stable identifier — either a canonical pattern slug ("multi_turn_crescendo") or a correlator Type ("high_severity_turn"). */
  signal: string;
  /** This signal's contribution to session_risk_score. 0-1, rounded to 2dp. */
  delta: number;
}

/**
 * Cooperative Governance action (four-state contract: allow / warn / require_approval / block).
 * Surfaced as the top-level `refuse_tier` field on every sanitized response
 * so callers can distinguish allow / warn / require_approval / block without
 * inferring from `action` + `blocked`. Contract-symmetric — present on safe
 * responses too (as "allow" or "warn").
 */
export type RefuseTier = 'allow' | 'warn' | 'require_approval' | 'block';

/**
 * Recovery guidance block emitted by the backend on refuse verdicts.
 * `instruction` is the canonical LockedSessionInstruction on session-locked
 * verdicts; `available_tools` names the MCP tools the caller may still
 * invoke while under quarantine (typically read-only surfaces such as
 * `session_status`); `patterns_triggered` scopes to THIS event and takes
 * precedence over session-level `session_state.session_patterns` when both
 * are present (see the MCP session-state extension).
 */
export interface Recovery {
  instruction?: string;
  available_tools?: string[];
  patterns_triggered?: string[];
}

/**
 * Audit block for compliance-ready responses.
 *
 * Historical note: this block carried `session_risk_score` and
 * `correlation_patterns` in prior releases. Those fields have moved to the
 * top-level `session_state` block on the sanitized response, so integrators
 * reading L9 state don't have to reach into an audit sub-object. See
 * SessionState above.
 */
export interface AuditBlock {
  scan_id: string;
  timestamp: string;
  policy_name?: string;
  framework_references?: string[];
}

/**
 * Client-side session rotation record, emitted on the response that
 * triggered the rotation (module-owned) or a rotation recommendation
 * (caller-owned). Discriminated union on `rotated`. See
 * config.SessionRotation for the source of truth on the fields.
 *
 * Two shapes, one per ownership case:
 *
 *   `rotated: true` (module-owned): the MCP client's fallback SESSION_ID
 *   was in force when the trigger fired. MCP mutated its module SESSION_ID
 *   in place. Fields: previous_session_id, new_session_id.
 *
 *   `rotated: false, rotation_recommended: true` (caller-owned): the
 *   caller supplied their own session_id on the tool call. MCP does NOT
 *   mutate anything — session lifecycle is the caller's responsibility.
 *   Fields: current_session_id (echoed back), suggested_new_session_id.
 *
 * Absent when no rotation trigger fired, which is the vast majority of
 * responses. Integrators can key on the presence of this field to detect
 * "the session risk crossed the threshold on this response" and surface
 * the explanation to their user or auto-adopt the new session_id.
 */
export interface ModuleOwnedRotationRecord {
  rotated: true;
  owner: 'mcp_client';
  reason: 'session_locked' | 'risk_threshold_exceeded';
  previous_session_id: string;
  new_session_id: string;
  triggering_risk_score?: number;
  configured_threshold?: number;
}

export interface CallerOwnedRotationRecommendationRecord {
  rotated: false;
  rotation_recommended: true;
  owner: 'caller';
  reason: 'session_locked' | 'risk_threshold_exceeded';
  current_session_id: string;
  suggested_new_session_id: string;
  triggering_risk_score?: number;
  configured_threshold?: number;
}

export type ClientSessionRotation = ModuleOwnedRotationRecord | CallerOwnedRotationRecommendationRecord;

/**
 * Per-item violation shape mirroring the SDK contract
 * (see `sdks/typescript/src/scanner.ts` — ScanViolation and
 * `sdks/python/src/shrike_guard/scanner.py` — ScanViolation). Populated on
 * MCP responses so callers with SDK-shape parse logic work verbatim against
 * MCP output. Attribution stripped: no policy_id/policy_name/matched_pattern/
 * detected_by/scan_stage/confidence — those are provider-only per
 * the dashboard IP boundary.
 */
export interface SanitizedViolation {
  threat_type: ThreatType;
  owasp_category: string;
  severity: Severity;
  action?: string;
  user_message?: string;
  suggested_action?: string;
}

/**
 * Sanitized response for blocked/flagged threats (external-facing)
 */
export interface SanitizedBlockedResponse {
  /**
   * Inverse of `blocked` — always present so SDK-shape parsers
   * (`if (r.safe) ...`) work verbatim against MCP output. See
   * the symmetric-contract principle: MCP is a superset of SDK, not
   * a divergent shape.
   */
  safe: false;
  blocked: true;
  action: 'block';
  threat_type: ThreatType;
  owasp_category: string;
  severity: Severity;
  confidence: ConfidenceBucket;
  guidance: string;
  agent_instruction: string;
  user_message: string;
  audit: AuditBlock;
  /**
   * L9 session state, populated whenever the caller supplied session_id
   * or agent_id. Absent when no session identity was provided.
   * See SessionState.
   */
  session_state?: SessionState;
  /**
   * Cooperative Governance refuse tier.
   * Server-authoritative. On a block response this will be "block"; on
   * approval it will be "require_approval". Present on every response for
   * contract symmetry. Absent only when older backends omit it.
   */
  refuse_tier?: RefuseTier;
  /**
   * Recovery guidance block. Populated on refuse verdicts —
   * carries the canonical LockedSessionInstruction on session-locked
   * responses, plus the tools still callable under quarantine.
   */
  recovery?: Recovery;
  /**
   * Specialized scan input type, e.g. "sql" / "file_path" / "a2a_message" /
   * "agent_card" / "command". Present on specialized-scan responses only.
   */
  content_type?: string;
  /**
   * Per-violation attribution mirroring the SDK contract. Primary violation
   * is duplicated at top-level (threat_type/owasp_category/severity) — the
   * array carries any additional violations detected on the same request.
   * Present on refuse verdicts only.
   */
  violations?: SanitizedViolation[];
  /**
   * Client-side session rotation record. Present only on
   * the response that triggered a rotation of the client's fallback
   * SESSION_ID. See ClientSessionRotation.
   */
  client_session_rotation?: ClientSessionRotation;
  request_id: string;
}

/**
 * Sanitized response for allowed requests (external-facing)
 */
export interface SanitizedAllowedResponse {
  /**
   * SDK-shape mirror of `!blocked`. Always present. See SanitizedBlockedResponse.
   */
  safe: true;
  blocked: false;
  action: 'allow';
  agent_instruction: string;
  audit: AuditBlock;
  /**
   * L9 session state, populated whenever the caller supplied session_id
   * or agent_id. Absent when no session identity was provided.
   * See SessionState.
   */
  session_state?: SessionState;
  /**
   * Cooperative Governance refuse tier. On safe responses this
   * is either "allow" or "warn" — the presence of the field lets callers
   * distinguish the advisory-warn state without re-inferring from action.
   */
  refuse_tier?: RefuseTier;
  /**
   * Recovery guidance block — populated on `warn` responses to surface
   * advisory copy the caller can echo to the user without refusing the call.
   */
  recovery?: Recovery;
  /**
   * Specialized scan input type — present on specialized-scan safe responses.
   */
  content_type?: string;
  /**
   * Symmetric with the block/approval variants — carries advisory
   * violations on `warn` verdicts. Absent (or empty) on clean allow.
   */
  violations?: SanitizedViolation[];
  /**
   * Client-side session rotation record. Present only on
   * the response that triggered a rotation of the client's fallback
   * SESSION_ID. See ClientSessionRotation.
   */
  client_session_rotation?: ClientSessionRotation;
  request_id: string;
}

/**
 * Sanitized response for actions requiring human approval (external-facing)
 */
export interface SanitizedApprovalResponse {
  /**
   * SDK-shape mirror — approval is a refuse verdict (not a hard block), so
   * safe is false. Callers that key on `if (r.safe) proceed()` will hold
   * on approval responses exactly as they hold on block responses.
   */
  safe: false;
  blocked: true;
  action: 'require_approval';
  approval_id: string;
  approval_context: {
    action_summary: string;
    policy_name: string;
    approval_level: string;
    expires_in_seconds: number;
    // Threat context for block-override approvals
    threat_type?: string;
    severity?: string;
    owasp_category?: string;
    risk_factors?: string[];
    original_action?: string; // "block" when overriding a block verdict
    // 2026-07-01: Agent-contract signal. "blocking" = park dependent work;
    // "advisory" = agent may defer this task while waiting. Defaults to
    // "advisory" pre-launch. See checkApproval.ts + scan.ts descriptions.
    enforcement_severity?: 'blocking' | 'advisory';
    expected_response_by_seconds?: number;
  };
  agent_instruction: string;
  user_message: string;
  audit: AuditBlock;
  /**
   * Resolution channel for this approval verdict.
   *   - "in_band"     — an approval_id was minted; the caller can poll
   *                     check_approval and resolve the verdict inside the
   *                     current tool cascade.
   *   - "out_of_band" — no approval_id was minted (e.g. Scope Tier 1 scope
   *                     violation); the caller must NOT call check_approval,
   *                     and the verdict resolves via the Shrike dashboard
   *                     or by policy/scope adjustment.
   * Absent on responses that predate the field — treat absent as "in_band"
   * for backward compat.
   */
  resolution?: 'in_band' | 'out_of_band';
  /**
   * L9 session state, populated whenever the caller supplied session_id
   * or agent_id. Present on approval responses for the same reason it's
   * present on allow + block responses: the symmetric-contract invariant
   * ("every scan response carries session_state") is what integrators
   * build governance policies on. Approval responses are precisely the
   * responses where accumulated session risk is most likely elevated —
   * omitting the block here would break the `if (response.session_state
   * .session_risk_score > threshold)` pattern on the response type most
   * likely to hit the threshold. See the symmetric-contract principle.
   */
  session_state?: SessionState;
  /**
   * Cooperative Governance refuse tier — always "require_approval" on the
   * approval response, but the field is present for contract symmetry so
   * callers can key policy on `refuse_tier` alone without discriminating on
   * `action`.
   */
  refuse_tier?: RefuseTier;
  /**
   * Recovery guidance block — approval verdicts may carry recovery copy
   * describing what the caller can do while awaiting sign-off (e.g. read-only
   * status checks).
   */
  recovery?: Recovery;
  /**
   * Specialized scan input type — present on specialized-scan approval responses.
   */
  content_type?: string;
  /**
   * Per-violation attribution — approval responses carry the underlying
   * violations that triggered the require_approval verdict, symmetric with
   * the block variant so SDK-shape parsers work on both.
   */
  violations?: SanitizedViolation[];
  /**
   * Client-side session rotation record. Present only on
   * the response that triggered a rotation of the client's fallback
   * SESSION_ID.
   */
  client_session_rotation?: ClientSessionRotation;
  request_id: string;
}

/**
 * Union type for all sanitized responses
 */
export type SanitizedResponse = SanitizedBlockedResponse | SanitizedAllowedResponse | SanitizedApprovalResponse;

/**
 * Internal log entry structure (for server-side debugging)
 */
export interface InternalLogEntry {
  request_id: string;
  timestamp: string;
  customer_id: string;
  tool_name: string;
  blocked: boolean;
  threat_type?: string;
  raw_confidence?: number;
  detection_layers: string[];
  policy_ids: string[];
  matched_patterns: string[];
  llm_analysis?: {
    confidence: number;
    reasoning: string;
    detected_by: string;
  };
  performance_metrics?: {
    total_scan_time_ms: number;
    policies_evaluated: number;
  };
}

// ============================================================================
// Guidance Map
// ============================================================================

/**
 * User-friendly guidance text for each threat type.
 * Explains what was detected WITHOUT revealing how it was detected.
 */
const THREAT_GUIDANCE: Record<ThreatType, string> = {
  prompt_injection:
    'This prompt contains patterns consistent with instruction override attempts. Review the source content for embedded commands.',
  jailbreak:
    'This prompt attempts to bypass safety guidelines. The request has been blocked.',
  system_prompt_leak:
    'The LLM response contains system prompt or internal configuration disclosure, indicating a successful jailbreak. The response has been blocked.',
  data_exfiltration:
    'This prompt may attempt to extract sensitive information. Review for PII or credential exposure patterns.',
  sql_injection:
    'This query contains potentially dangerous SQL patterns. Review for unauthorized data access or modification attempts.',
  path_traversal:
    'This file path attempts to access directories outside the allowed scope. Review for directory traversal patterns.',
  secrets_exposure:
    'This content contains patterns matching API keys, tokens, or credentials. Avoid committing secrets to files.',
  pii_exposure:
    'This content contains personally identifiable information. Consider redacting before processing.',
  blocked_domain:
    'This web search targets a restricted domain. Review your organization\'s acceptable use policy.',
  toxic_content:
    'This content contains potentially harmful or inappropriate language. Review before proceeding.',
  toxicity:
    'This content contains potentially harmful or inappropriate language. Review before proceeding.',
  multi_turn_attack:
    'A pattern was detected across multiple turns of this session that suggests a coordinated attempt to bypass safety controls. Review prior turns and consider resetting the session.',
  session_locked:
    'This session has been quarantined due to accumulated risk across multiple prior turns. Further requests on this session will be blocked. Start a fresh session to continue.',
  malicious_code:
    'This content contains patterns associated with malicious code such as reverse shells, web shells, or persistence mechanisms. The file has been blocked.',
  harmful_intent:
    'This request contains content associated with harmful or dangerous intent. The request has been blocked.',
  social_engineering:
    'This prompt contains social engineering patterns such as authority claims, urgency pressure, or trust manipulation.',
  privilege_escalation:
    'This query attempts to escalate privileges, modify user roles, or gain unauthorized access.',
  destructive_operation:
    'This query contains destructive operations such as DROP TABLE, TRUNCATE, or mass DELETE. Review carefully before executing.',
  scan_error:
    'The security scan could not be completed. The request has been blocked as a precaution.',
  size_limit_exceeded:
    'The content exceeds the maximum allowed size. Please reduce the content size and retry.',
  unknown:
    'A security concern was detected. Please review the content and retry.',
};

// ============================================================================
// OWASP LLM Top 10 Mapping
// ============================================================================

/**
 * Maps each threat type to the relevant OWASP LLM Top 10 category.
 *
 * Aligned to the OWASP LLM Top 10 2026 edition (adopted 2026-08-05), which
 * renumbered several categories vs. 2025. This map MUST agree with the
 * backend's models.MapLegacyThreatTypeToOWASP (single source of truth).
 * 2026 moves reflected here: Improper Output Handling LLM05→LLM10,
 * Excessive Agency LLM06→LLM03, System Prompt Leakage LLM07→"Hidden Context
 * Exposure" LLM08, Unbounded Consumption LLM10→LLM06, Misinformation LLM09→LLM07.
 */
const OWASP_MAPPING: Record<ThreatType, string> = {
  prompt_injection: 'LLM01',
  jailbreak: 'LLM01',
  system_prompt_leak: 'LLM08', // 2026: Hidden Context Exposure (was LLM07 System Prompt Leakage)
  data_exfiltration: 'LLM02',
  sql_injection: 'LLM10', // 2026: Improper Output Handling (was LLM05)
  path_traversal: 'LLM10', // 2026: Improper Output Handling
  secrets_exposure: 'LLM02',
  pii_exposure: 'LLM02',
  blocked_domain: 'LLM10', // 2026: Improper Output Handling
  toxic_content: 'LLM07', // 2026: Misinformation (model-produced harmful text)
  toxicity: 'LLM07', // 2026: Misinformation
  multi_turn_attack: 'LLM01', // multi-turn correlation is a prompt-injection-class concern
  session_locked: 'LLM01', // Quarantine is a session-level extension of the prompt-injection category
  malicious_code: 'LLM10', // 2026: Improper Output Handling (was LLM05)
  harmful_intent: 'LLM01',
  social_engineering: 'LLM01',
  privilege_escalation: 'LLM03', // 2026: Excessive Agency (was LLM06)
  destructive_operation: 'LLM03', // 2026: Excessive Agency (was LLM06)
  scan_error: 'LLM01',
  size_limit_exceeded: 'LLM06', // 2026: Unbounded Consumption (was LLM10)
  unknown: 'LLM01',
};

// ============================================================================
// User-Safe Messages (no detection details leaked)
// ============================================================================

/**
 * Safe messages for end users per threat type.
 * These never reveal how detection works.
 */
const USER_MESSAGES: Record<ThreatType, string> = {
  prompt_injection:
    'Your message was blocked by security policy. It contains content that cannot be processed. Please rephrase your request.',
  jailbreak:
    'Your message was blocked by security policy. It contains content that cannot be processed. Please rephrase your request.',
  system_prompt_leak:
    'This response was blocked by security policy. It contains internal configuration that cannot be disclosed.',
  data_exfiltration:
    'Your request was blocked by security policy. It contains patterns that could expose sensitive data.',
  sql_injection:
    'This database query was blocked by security policy. It contains patterns that could compromise data integrity. Please reformulate.',
  path_traversal:
    'This file operation was blocked by security policy. The path targets a restricted location.',
  secrets_exposure:
    'This content was blocked by security policy. It contains credentials or secrets that should not be stored here.',
  pii_exposure:
    'This content was blocked by security policy. It contains personally identifiable information that requires handling per data policy.',
  blocked_domain:
    'This request was blocked by security policy. The target domain is restricted.',
  toxic_content:
    'This content was blocked by security policy. It contains language that violates acceptable use guidelines.',
  toxicity:
    'This content was blocked by security policy. It contains language that violates acceptable use guidelines.',
  multi_turn_attack:
    'This conversation was paused by security policy. A pattern across multiple turns suggests a coordinated attempt to bypass safety controls.',
  session_locked:
    'This session has been paused by security policy. Accumulated risk across prior turns exceeded the safe threshold. Please start a new session to continue.',
  malicious_code:
    'This content was blocked by security policy. It contains code patterns that are not permitted.',
  harmful_intent:
    'Your request was blocked by security policy. It contains content associated with harmful intent.',
  social_engineering:
    'Your message was blocked by security policy. It contains manipulation patterns that cannot be processed.',
  privilege_escalation:
    'This operation was blocked by security policy. It attempts to modify access controls or escalate privileges.',
  destructive_operation:
    'This operation was blocked by security policy. It contains destructive commands that require explicit authorization.',
  scan_error:
    'The security scan could not be completed. The request has been blocked as a precaution. Please retry.',
  size_limit_exceeded:
    'The content exceeds the maximum allowed size. Please reduce the content size and retry.',
  unknown:
    'Your request was blocked by security policy. Please review the content and retry.',
};

// ============================================================================
// Agent Instructions (per tool, for blocked responses)
// ============================================================================

/**
 * Recommended actions for the AI agent when content is blocked.
 * These are advisory — the scan verdict is data, not a behavioral directive.
 * Keyed by tool name.
 */
const AGENT_INSTRUCTIONS_BLOCKED: Record<string, string> = {
  scan_prompt:
    'Verdict: BLOCKED. This input was flagged as unsafe. Recommended action: skip processing and return the user_message to the caller.',
  scan_response:
    'Verdict: BLOCKED. This LLM response was flagged as unsafe. Recommended action: regenerate with a modified prompt or return the user_message as a safe fallback.',
  scan_sql_query:
    'Verdict: BLOCKED. This SQL query was flagged as unsafe. Recommended action: skip execution and return the user_message to the caller. Log the audit fields for security review.',
  scan_file_write:
    'Verdict: BLOCKED. This file write was flagged as unsafe (content or destination). Recommended action: skip the write and return the user_message to the caller.',
  scan_web_search:
    'Verdict: BLOCKED. This search query was flagged — it may contain information that should not be sent to external search engines. Recommended action: skip execution and return the user_message.',
  scan_command:
    'Verdict: BLOCKED. This command was flagged for unsafe patterns (data exfiltration, destructive operations, or privilege escalation). Recommended action: skip execution and return the user_message to the caller.',
  scan_a2a_message:
    'Verdict: BLOCKED. This A2A message was flagged for injection or exfiltration patterns. Recommended action: skip processing and return the user_message to the caller.',
  scan_agent_card:
    'Verdict: BLOCKED. This agent card was flagged for suspicious patterns (injection, spoofing, or suspicious URLs). Recommended action: skip connection and return the user_message to the caller.',
};

const AGENT_INSTRUCTION_ALLOWED = 'Content is safe. Proceed with normal processing.';

/**
 * Terse per-violation descriptors keyed by normalized threat_type.
 *
 * These populate `violation.user_message` — the SHORT label shown alongside
 * each entry in a multi-violation response. Distinct from USER_MESSAGES, which
 * are the top-level end-user messages (longer, one per response, not per
 * violation).
 *
 * Rationale: the backend sometimes returns policy metadata (e.g. the literal
 * policy name "Security Policy") in the violation's message field, which
 * leaks upstream as a useless placeholder in `violations[].user_message`.
 * Using this map instead gives every violation a stable, terse, human-facing
 * label without exposing detector internals.
 *
 * Keep entries under ~60 characters. They must be safe to show to end users
 * (no attack payload echo, no detector attribution).
 */
const VIOLATION_MESSAGES: Record<ThreatType, string> = {
  prompt_injection: 'Instruction-override phrasing detected',
  jailbreak: 'Safety-bypass attempt detected',
  system_prompt_leak: 'System-prompt disclosure attempt detected',
  data_exfiltration: 'System-prompt / data extraction attempt',
  sql_injection: 'SQL injection pattern detected',
  path_traversal: 'Path-traversal pattern detected',
  secrets_exposure: 'Credentials or secrets detected in content',
  pii_exposure: 'Personally identifiable information detected',
  blocked_domain: 'Blocked domain referenced',
  toxic_content: 'Toxic-content pattern detected',
  toxicity: 'Toxic-content pattern detected',
  multi_turn_attack: 'Multi-turn attack pattern detected',
  session_locked: 'Session risk exceeded safe threshold',
  malicious_code: 'Malicious-code pattern detected',
  harmful_intent: 'Harmful-intent pattern detected',
  social_engineering: 'Social-engineering pattern detected',
  privilege_escalation: 'Privilege-escalation pattern detected',
  destructive_operation: 'Destructive-operation pattern detected',
  scan_error: 'Scan could not complete',
  size_limit_exceeded: 'Content exceeds maximum size',
  unknown: 'Policy violation detected',
};

/**
 * Backend-provided violation messages that are actually placeholders (the
 * policy name leaked through). Filter these before falling back to the
 * VIOLATION_MESSAGES map. Match is case-insensitive and trimmed.
 */
const VIOLATION_MESSAGE_PLACEHOLDERS: ReadonlySet<string> = new Set([
  'security policy',
  'policy',
  'blocked',
  'violation',
  '',
]);

function violationUserMessage(threat: ThreatType, backendMessage?: string): string {
  if (backendMessage) {
    const trimmed = backendMessage.trim();
    if (trimmed && !VIOLATION_MESSAGE_PLACEHOLDERS.has(trimmed.toLowerCase())) {
      return trimmed;
    }
  }
  return VIOLATION_MESSAGES[threat];
}

// ============================================================================
// Framework References
// ============================================================================

/**
 * Maps threat types to compliance framework references.
 */
function getFrameworkRefs(threatType: ThreatType): string[] {
  const refs: Partial<Record<ThreatType, string[]>> = {
    sql_injection: ['SOC2 CC6.1', 'PCI-DSS 6.5.1'],
    pii_exposure: ['GDPR Art.5', 'HIPAA 164.514'],
    secrets_exposure: ['SOC2 CC6.1'],
    data_exfiltration: ['SOC2 CC6.1', 'GDPR Art.5'],
    system_prompt_leak: ['SOC2 CC6.1'],
    path_traversal: ['SOC2 CC6.1'],
    privilege_escalation: ['SOC2 CC6.1'],
    destructive_operation: ['SOC2 CC6.1'],
    malicious_code: ['SOC2 CC6.1'],
  };
  return refs[threatType] || [];
}

// ============================================================================
// Core Utility Functions
// ============================================================================

/**
 * Generates a unique request ID for traceability.
 * Format: req_<timestamp_base36>_<random_8chars>
 */
/**
 * Inspect a sanitized scan response for rotation triggers
 * (session_locked verdict, or session_state.session_risk_score above
 * threshold), and if a rotation happens, attach the record on the
 * outbound response.
 *
 * Called at every sanitizer's return path so the client's SESSION_ID
 * rotates exactly once per triggering response and the caller sees a
 * `client_session_rotation` field alongside `session_state`. See
 * config.rotateSessionIfTriggered for the trigger logic and env vars.
 *
 * Structural typing keeps this compatible with all three sanitized
 * response shapes without importing them explicitly, which would create
 * an awkward union at the call site.
 */
function finalizeWithRotation<T extends { threat_type?: string; session_state?: SessionState; client_session_rotation?: ClientSessionRotation }>(
  response: T,
  effective_session_id: string,
): T {
  const rotation = rotateSessionIfTriggered({
    threat_type: response.threat_type,
    session_state: response.session_state,
    effective_session_id,
  });
  if (rotation) {
    response.client_session_rotation = rotation;
  }
  return response;
}

export function generateRequestId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `req_${timestamp}_${random}`;
}

/**
 * Converts numeric confidence (0.0-1.0) to bucketed level.
 * Protects IP by not exposing exact thresholds.
 */
export function bucketConfidence(score: number): ConfidenceBucket {
  if (score >= 0.9) return 'high';
  if (score >= 0.7) return 'medium';
  return 'low';
}

/**
 * Maps internal threat types to normalized external types.
 * Normalizes the variety of internal threat type names to a consistent set.
 */
export function normalizeThreatType(internalType: string): ThreatType {
  const normalized = internalType.toLowerCase().replace(/[_-]/g, '_');

  const mapping: Record<string, ThreatType> = {
    // Prompt injection variants (from LLM intent and categories)
    prompt_injection: 'prompt_injection',
    injection: 'prompt_injection',
    inject: 'prompt_injection',      // LLM intent: INJECT
    instruction_override: 'prompt_injection',
    role_hijacking: 'prompt_injection',
    context_manipulation: 'prompt_injection',
    token_manipulation: 'prompt_injection',   // LLM category: spaced chars, l33t speak
    indirect_injection: 'prompt_injection',   // Document parser: hidden text attacks
    context_poisoning: 'prompt_injection',    // Multi-turn attacks
    function_injection: 'prompt_injection',   // Tool/function injection
    memory_injection: 'prompt_injection',     // False memory attacks

    // Jailbreak variants (from LLM analyzer categories)
    jailbreak: 'jailbreak',
    jailbreak_attempt: 'jailbreak',
    safety_bypass: 'jailbreak',
    roleplay: 'jailbreak',           // LLM category: roleplay attacks (DAN, etc.)
    hypothetical: 'jailbreak',       // LLM category: hypothetical/academic framing
    social_engineering: 'social_engineering', // LLM category: authority/urgency manipulation
    completion_baiting: 'jailbreak', // LLM category: continue harmful content
    emotional: 'social_engineering',  // LLM category: emotional manipulation
    override: 'jailbreak',           // LLM intent: OVERRIDE
    manipulate: 'jailbreak',         // LLM intent: MANIPULATE
    // Toxic content — canonical name as of the L7 rewrite. `toxicity` kept as
    // a legacy alias so older backend builds + customer code don't break.
    toxic_content: 'toxic_content',
    toxicity: 'toxic_content',
    harmful_content: 'toxic_content',
    // L9 multi-turn pseudo-category — see prefix handling in normalizeThreatType.
    multi_turn_attack: 'multi_turn_attack',
    // Q1 session-quarantine short-circuit — backend emits this when accumulated
    // L9 risk >= 0.8. Not a per-turn detection; a session-level verdict.
    session_locked: 'session_locked',

    // Data exfiltration (from LLM intent and categories)
    data_exfiltration: 'data_exfiltration',
    exfiltration: 'data_exfiltration',
    exfiltrate: 'data_exfiltration', // LLM intent: EXFILTRATE
    extract: 'data_exfiltration',    // LLM intent: EXTRACT
    data_leak: 'data_exfiltration',
    information_disclosure: 'data_exfiltration',
    system_prompt_extraction: 'system_prompt_leak',  // Reveal system prompt
    system_prompt_leak: 'system_prompt_leak',        // L8 Response Intelligence: system prompt leaked in response
    credential_extraction: 'data_exfiltration',

    // L8 Response Intelligence anomaly types
    unexpected_pii_leakage: 'pii_exposure',         // L8: PII in response not in prompt
    // L8 tonality drift — backend normalizes profanity + hostile to toxic_content;
    // casual stays as jailbreak (matches platform/common/models/response.go:309-313).
    tonality_drift_profanity: 'toxic_content',      // L8: profanity in response
    tonality_drift_hostile: 'toxic_content',        // L8: hostile language in response
    tonality_drift_casual: 'jailbreak',             // L8: casual tone (persona adoption)
    topic_mismatch: 'prompt_injection',             // L8: response topic differs from prompt

    // SQL injection
    sql_injection: 'sql_injection',
    sqli: 'sql_injection',
    tautology: 'sql_injection',
    tautology_or: 'sql_injection',
    tautology_and: 'sql_injection',
    union_injection: 'sql_injection',
    stacked_query: 'sql_injection',

    // Path traversal
    path_traversal: 'path_traversal',
    directory_traversal: 'path_traversal',
    path_violation: 'path_traversal',
    file_access: 'path_traversal',
    sensitive_path: 'path_traversal',

    // Secrets (from backend path_validator.go)
    secrets_exposure: 'secrets_exposure',
    secrets: 'secrets_exposure',
    api_key: 'secrets_exposure',
    credential: 'secrets_exposure',
    sensitive_file: 'secrets_exposure',
    content_violation: 'secrets_exposure',
    sensitive_content: 'secrets_exposure',  // Backend sends this for secrets
    secret_key: 'secrets_exposure',
    aws_key: 'secrets_exposure',
    private_key: 'secrets_exposure',

    // PII (from LLM pii_extraction category and path_validator)
    pii_exposure: 'pii_exposure',
    pii: 'pii_exposure',
    pii_leak: 'pii_exposure',
    personal_data: 'pii_exposure',
    pii_in_search: 'pii_exposure',
    pii_extraction: 'pii_exposure',  // LLM category: PII extraction attempts
    ssn: 'pii_exposure',
    credit_card: 'pii_exposure',
    email_exposure: 'pii_exposure',
    phone_number: 'pii_exposure',
    health_record: 'pii_exposure',   // PHI/HIPAA
    medical_data: 'pii_exposure',
    patient_data: 'pii_exposure',

    // Domain blocking
    blocked_domain: 'blocked_domain',
    suspicious_tld: 'blocked_domain',
    suspicious_domain: 'blocked_domain',  // Domains with malicious keywords
    malicious_url: 'blocked_domain',

    // Malicious code (shells, miners, etc.) - maps to standard "malicious_code"
    malicious_content: 'malicious_code',  // Backend path_validator type
    malicious_code: 'malicious_code',     // Standard category
    reverse_shell: 'malicious_code',
    web_shell: 'malicious_code',
    fork_bomb: 'malicious_code',
    crypto_miner: 'malicious_code',
    persistence: 'malicious_code',
    shell_injection: 'malicious_code',

    // Harmful intent
    harmful_intent: 'harmful_intent',
    dangerous_request: 'harmful_intent',

    // Social engineering (additional mappings)
    authority_claim: 'social_engineering',

    // Privilege escalation (from SQL detector)
    privilege_escalation: 'privilege_escalation',

    // Destructive operations (from SQL detector)
    destructive_operation: 'destructive_operation',

    // Path/extension blocking
    sensitive_extension: 'path_traversal',  // Blocked file extension → path category
    blocked_extension: 'path_traversal',

    // Errors
    scan_error: 'scan_error',
    size_limit_exceeded: 'size_limit_exceeded',
    size_limit: 'size_limit_exceeded',
    timeout: 'scan_error',
  };

  if (mapping[normalized]) {
    return mapping[normalized];
  }
  // L9 multi-turn correlation patterns flow as `multi_turn_<pattern>`
  // (crescendo, blocked_retry, topic_pivot, threat_diversity, safe_then_unsafe,
  // tool_sequence_anomaly, coded_language_setup, context_overflow,
  // memory_poisoning, velocity_burst). Backend collapses these to
  // multi_turn_attack — mirror the prefix logic from
  // platform/common/models/response.go:380.
  if (normalized.startsWith('multi_turn_')) {
    return 'multi_turn_attack';
  }
  return 'unknown';
}

/**
 * Gets guidance text for a threat type.
 */
export function getGuidance(threatType: ThreatType): string {
  return THREAT_GUIDANCE[threatType] || THREAT_GUIDANCE.unknown;
}

/**
 * Determines the highest severity from a list.
 */
export function getHighestSeverity(severities: string[]): Severity {
  const order: Severity[] = ['critical', 'high', 'medium', 'low'];
  for (const level of order) {
    if (severities.some((s) => s.toLowerCase() === level)) {
      return level;
    }
  }
  return 'medium';
}

// ============================================================================
// Internal Logging
// ============================================================================

/**
 * Logs full internal details to stderr for debugging.
 * This preserves all IP-sensitive information server-side.
 *
 * Uses stderr to avoid interfering with MCP JSON-RPC on stdout.
 */
export function logInternalDetails(entry: InternalLogEntry): void {
  const logEntry = {
    level: 'info',
    type: 'scan_detail',
    ...entry,
  };

  // Use console.error (stderr) to avoid interfering with MCP protocol on stdout
  console.error(JSON.stringify(logEntry));
}

// ============================================================================
// Sanitization Functions for Each Tool Type
// ============================================================================

/**
 * Internal result type from scan.ts (for type safety)
 */
interface InternalScanResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'redact' | 'block';
  violations: Array<{
    threatType: string;
    severity: string;
    confidence: number;
    action: string;
    detectedBy: string;
    message: string;
    policyId: string;
    policyName: string;
    scanStage?: string;
    matchedPattern?: string;
  }>;
  llmAnalysis?: {
    analyzed: boolean;
    isMalicious: boolean;
    confidence: number;
    threatType: string;
    reasoning: string;
    detectedBy: string;
    analysisTimeMs: number;
    providerSafetyBlock?: {
      triggered: boolean;
      reason: string;
      message: string;
      source: string;
    };
  };
  performance: {
    totalScanTimeMs: number;
    policiesEvaluated: number;
    llmAnalysisUsed: boolean;
    cacheHits: number;
  };
  approvalInfo?: {
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
    // 2026-07-01: Agent-contract signal (see checkApproval.ts)
    enforcement_severity?: 'blocking' | 'advisory';
    expected_response_by_seconds?: number;
  };
  /**
   * L9 session state carried from backend response. Mapped through to the
   * top-level `session_state` field on the SanitizedResponse — see
   * SessionState above. Populated whenever the backend correlator had
   * session identity to work with.
   */
  sessionState?: SessionState;
  /**
   * Cooperative Governance refuse tier. Forwarded verbatim
   * from the backend response to the sanitized top-level `refuse_tier`
   * field. See responseFormatter.RefuseTier.
   */
  refuseTier?: RefuseTier;
  /**
   * Recovery guidance block. Forwarded verbatim from the
   * backend to the sanitized top-level `recovery` field on refuse verdicts.
   */
  recovery?: Recovery;
  /**
   * Specialized scan input type. Present on specialized
   * scans only — surfaced as top-level `content_type` on the wire.
   */
  contentType?: string;
}

/**
 * Internal result type from specialized scans (SQL, file, web)
 */
interface InternalSpecializedResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'block';
  issues: Array<{
    type: string;
    severity: string;
    message: string;
    pattern?: string;
    position?: number;
    location?: string;
  }>;
  metadata: {
    scanTimeMs: number;
    [key: string]: unknown;
  };
  approvalInfo?: {
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
    // 2026-07-01: Agent-contract signal (see checkApproval.ts)
    enforcement_severity?: 'blocking' | 'advisory';
    expected_response_by_seconds?: number;
  };
  /**
   * L9 session state carried from backend response. Symmetric with the
   * general-scan sanitizer (sanitizeScanResult) — act-plane specialized
   * tools carry the same block shape as observe-plane content scans.
   * See SessionState.
   */
  sessionState?: SessionState;
  /**
   * Cooperative Governance refuse tier — same contract as
   * on the general-scan result. Forwarded to top-level `refuse_tier`.
   */
  refuseTier?: RefuseTier;
  /**
   * Recovery guidance block — same contract as on the
   * general-scan result. Forwarded to top-level `recovery`.
   */
  recovery?: Recovery;
  /**
   * Specialized scan input type — surfaced as top-level `content_type`.
   */
  contentType?: string;
}

/**
 * Pick the governance-symmetry fields (refuse_tier / recovery / content_type)
 * from either internal result type, ready to spread into any sanitized
 * response. Empty object when none present — spread of {} is a no-op, so
 * every sanitizer can call this unconditionally.
 *
 * Contract symmetry: every sanitizer's return path must include this so
 * safe and refuse verdicts carry the same governance fields.
 */
function pickGovernanceFields(
  result: { refuseTier?: RefuseTier; recovery?: Recovery; contentType?: string },
): { refuse_tier?: RefuseTier; recovery?: Recovery; content_type?: string } {
  const out: { refuse_tier?: RefuseTier; recovery?: Recovery; content_type?: string } = {};
  if (result.refuseTier) out.refuse_tier = result.refuseTier;
  if (result.recovery) out.recovery = result.recovery;
  if (result.contentType) out.content_type = result.contentType;
  return out;
}

/**
 * Map a general-scan violations[] array into the SDK-shape SanitizedViolation
 * array on the wire. Attribution (policyId/policyName/matchedPattern/detectedBy/
 * scanStage/confidence) is stripped — that data stays server-side per
 * the dashboard IP boundary. Returns undefined when there are no
 * violations, so `...(violations ? { violations } : {})` collapses cleanly.
 */
function sanitizeViolations(
  violations: InternalScanResult['violations'] | undefined,
): SanitizedViolation[] | undefined {
  if (!violations || violations.length === 0) return undefined;
  return violations.map((v) => {
    const threat = normalizeThreatType(v.threatType || 'unknown');
    const owasp = OWASP_MAPPING[threat];
    const severity = getHighestSeverity([v.severity]);
    const out: SanitizedViolation = {
      threat_type: threat,
      owasp_category: owasp,
      severity,
      user_message: violationUserMessage(threat, v.message),
    };
    if (v.action) out.action = v.action;
    return out;
  });
}

/**
 * Map a specialized-scan issues[] array into the SDK-shape SanitizedViolation
 * array. Same attribution strip as sanitizeViolations — pattern/position/
 * location are provider-only.
 */
function sanitizeSpecializedIssues(
  issues: InternalSpecializedResult['issues'] | undefined,
): SanitizedViolation[] | undefined {
  if (!issues || issues.length === 0) return undefined;
  return issues.map((i) => {
    const threat = normalizeThreatType(i.type || 'unknown');
    const owasp = OWASP_MAPPING[threat];
    const severity = getHighestSeverity([i.severity]);
    const out: SanitizedViolation = {
      threat_type: threat,
      owasp_category: owasp,
      severity,
      user_message: violationUserMessage(threat, i.message),
    };
    return out;
  });
}

/**
 * Builds a require_approval response from approval_info returned by the backend.
 *
 * sessionState is threaded through symmetrically — the require_approval branch
 * is a sanitized scan response like the allow and block branches, and the
 * symmetric-contract invariant (the symmetric-contract principle) requires
 * session_state on every response with session identity. Approval responses
 * are the branch most likely to hit elevated session risk, so omitting the
 * block here would break `if (r.session_state.session_risk_score > t)`
 * policy code on the exact response type that most needs it.
 */
function buildApprovalResponse(
  approvalInfo: NonNullable<InternalScanResult['approvalInfo']>,
  requestId: string,
  effective_session_id: string,
  sessionState?: SessionState,
  governance?: { refuseTier?: RefuseTier; recovery?: Recovery; contentType?: string },
  violations?: SanitizedViolation[],
): SanitizedApprovalResponse {
  const expiresMinutes = Math.ceil(approvalInfo.expires_in_seconds / 60);
  const isBlockOverride = approvalInfo.original_action === 'block';

  // Build approval context with optional threat fields
  const enforcementSeverity = approvalInfo.enforcement_severity || 'advisory';
  const expectedResponseBy = approvalInfo.expected_response_by_seconds ?? approvalInfo.expires_in_seconds;
  const approvalContext: SanitizedApprovalResponse['approval_context'] = {
    action_summary: approvalInfo.action_summary,
    policy_name: approvalInfo.policy_name,
    approval_level: approvalInfo.approval_level,
    expires_in_seconds: approvalInfo.expires_in_seconds,
    enforcement_severity: enforcementSeverity,
    expected_response_by_seconds: expectedResponseBy,
  };

  // Threat classification (threat_type / severity / owasp_category / risk_factors)
  // is surfaced on ANY approval that carries it — not only block-override ones.
  // Scope-Tier-1 events, on_safe approvals with a policy-attached threat, and
  // future require_approval sources all deserve the same classification field
  // surface. Missing "original_action" is the marker that distinguishes a
  // scope/policy approval from a block-override — that stays gated below.
  if (approvalInfo.threat_type) approvalContext.threat_type = approvalInfo.threat_type;
  if (approvalInfo.severity) approvalContext.severity = approvalInfo.severity;
  if (approvalInfo.owasp_category) approvalContext.owasp_category = approvalInfo.owasp_category;
  if (approvalInfo.risk_factors?.length) approvalContext.risk_factors = approvalInfo.risk_factors;
  if (isBlockOverride) {
    approvalContext.original_action = 'block';
  }

  const isBlocking = enforcementSeverity === 'blocking';

  // Differentiate messages for block-override vs on_safe approvals AND for
  // blocking vs advisory enforcement severity. Blocking means don't touch
  // dependent work; advisory means you may defer this task and continue.
  const cascadeGuidance = isBlocking
    ? 'This approval is BLOCKING: do NOT proceed with the original action and do NOT proceed with any downstream tasks that depend on this decision. Park the whole cascade until the human decides.'
    : 'This approval is ADVISORY: do NOT proceed with the original action, but you MAY defer this task and continue with unrelated work while waiting.';

  // Detect the out-of-band resolution channel: when the backend hasn't (yet)
  // created an approval record for the verdict (e.g. Scope Tier 1 scope
  // violation short-circuit before Tier 2 wiring), approvalInfo.approval_id
  // arrives undefined / empty. `check_approval` cannot resolve this — the
  // caller must be told explicitly not to try, and told where the real
  // resolution surface is instead.
  const hasApprovalId = !!approvalInfo.approval_id;
  const resolution: 'in_band' | 'out_of_band' = hasApprovalId ? 'in_band' : 'out_of_band';

  // Defensive rendering: emit a graceful message instead of
  // "Approval ID: undefined" / "NaN minutes" when the record was never minted.
  const approvalIdText = hasApprovalId
    ? `Approval ID: ${approvalInfo.approval_id}`
    : 'No approval ID has been issued yet — this verdict must be resolved out-of-band via your Shrike dashboard or by adjusting the policy/scope that triggered it';
  const expiresText = Number.isFinite(expiresMinutes) && expiresMinutes > 0
    ? `${expiresMinutes} minutes`
    : 'the default review window';

  // Three agent_instruction branches:
  //   1. out_of_band  — no approval_id; do NOT call check_approval.
  //   2. block-override in-band — action was BLOCKED but a human override
  //      was requested; approval_id present; check_approval will resolve.
  //   3. plain in-band — action requires approval; approval_id present;
  //      check_approval will resolve.
  // The out-of-band branch is the U2 fix from the 2026-07-09 consumer review:
  // the generic "wait for check_approval" instruction was misleading when no
  // approval_id had been minted.
  let agentInstruction: string;
  let userMessage: string;
  if (!hasApprovalId) {
    const threatLabel = approvalInfo.threat_type || 'policy violation';
    agentInstruction = `HOLD: This ${threatLabel} cannot be resolved in-band — no approval_id has been issued. Do NOT call check_approval. ${cascadeGuidance} Park the task and tell the user to resolve the verdict out-of-band via the Shrike dashboard or by adjusting the policy/scope that triggered it.`;
    userMessage = `This action requires human review, but no in-band approval channel is available for this verdict type. ${approvalIdText}. Please resolve via your Shrike dashboard or contact your security team.`;
  } else if (isBlockOverride) {
    agentInstruction = `HOLD: This action was BLOCKED by security policy (${approvalInfo.threat_type || 'threat detected'}) but an override approval has been requested. ${cascadeGuidance} Present the approval_context to the user including the threat type, severity, and risk factors. Do NOT poll in a loop. Wait for the user to instruct you to check the approval status using check_approval.`;
    userMessage = `This action was blocked by security policy (${approvalInfo.threat_type || 'threat detected'}) but a human override has been requested. ${approvalIdText}. A reviewer must approve or reject within ${expiresText}.`;
  } else {
    agentInstruction = `HOLD: This action requires human approval before proceeding. ${cascadeGuidance} Present the approval_context to the user (action summary, policy name, expiration, enforcement_severity). Do NOT poll in a loop. Wait for the user to instruct you to check the approval status using check_approval.`;
    userMessage = `This action requires approval from your security team before it can proceed. ${approvalIdText}. It will expire in ${expiresText} if not reviewed.`;
  }

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'require_approval' as const,
    approval_id: approvalInfo.approval_id,
    resolution,
    approval_context: approvalContext,
    agent_instruction: agentInstruction,
    user_message: userMessage,
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: approvalInfo.policy_name,
    },
    ...(sessionState ? { session_state: sessionState } : {}),
    ...(governance ? pickGovernanceFields(governance) : {}),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_prompt result.
 * Removes: detectedBy, policyId, matchedPattern, llmAnalysis details
 * Buckets: confidence scores
 * Adds: guidance text, action, agent_instruction, user_message, audit, owasp_category
 */
export function sanitizeScanResult(
  result: InternalScanResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_prompt',
): SanitizedResponse {
  const violations = sanitizeViolations(result.violations);

  // Check for approval requirement (on_safe or block-override)
  // Removed result.safe gate — block-override sets approvalInfo on blocked content
  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }

  // Safe results get minimal response
  // Note: PII redaction returns safe=true with recommendedAction='redact' — this is NOT a block
  if (result.safe && (result.recommendedAction === 'allow' || result.recommendedAction === 'redact')) {
    const audit: AuditBlock = {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
    };

    // Surface provider safety block as scan coverage degradation
    const providerBlock = result.llmAnalysis?.providerSafetyBlock;
    const response: SanitizedResponse = {
      safe: true,
      blocked: false,
      action: 'allow',
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit,
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    };
    if (providerBlock?.triggered) {
      (response as any).scan_coverage = {
        degraded: true,
        reason: 'llm_provider_safety_block',
        detail: `LLM analysis layer was blocked by the provider's safety guardrails (${providerBlock.reason}). Scan result is based on regex and pattern layers only.`,
      };
    }
    return finalizeWithRotation(response as any, effective_session_id);
  }

  // Get primary threat from violations
  const primaryViolation = result.violations[0];
  const threatType = normalizeThreatType(primaryViolation?.threatType || 'unknown');
  const severity = getHighestSeverity(
    result.violations.map((v) => v.severity)
  );
  const confidence = bucketConfidence(result.confidence);

  const blockedAudit: AuditBlock = {
    scan_id: requestId,
    timestamp: new Date().toISOString(),
    policy_name: primaryViolation?.policyName || 'Security Policy',
    framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
  };

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_prompt'],
    user_message: USER_MESSAGES[threatType],
    audit: blockedAudit,
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_sql_query result.
 */
export function sanitizeSQLResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_sql_query'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  // Removed result.safe gate — block-override sets approvalInfo on blocked content
  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'sql_injection');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_sql_query'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_file_write result.
 */
export function sanitizeFileWriteResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_file_write'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  // Removed result.safe gate — block-override sets approvalInfo on blocked content
  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'unknown');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_file_write'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_web_search result.
 */
export function sanitizeWebSearchResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_web_search'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  // Removed result.safe gate — block-override sets approvalInfo on blocked content
  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'blocked_domain');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_web_search'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_command result.
 */
export function sanitizeCommandResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_command'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  // block-override sets approvalInfo on blocked content
  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'malicious_code');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_command'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_a2a_message result.
 */
export function sanitizeA2AMessageResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_a2a_message'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'prompt_injection');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_a2a_message'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

/**
 * Sanitizes scan_agent_card result.
 */
export function sanitizeAgentCardResult(
  result: InternalSpecializedResult,
  requestId: string,
  effective_session_id: string,
  toolName: string = 'scan_agent_card'
): SanitizedResponse {
  const violations = sanitizeSpecializedIssues(result.issues);

  if (result.approvalInfo?.requires_approval) {
    return buildApprovalResponse(result.approvalInfo, requestId, effective_session_id, result.sessionState, result, violations);
  }
  if (result.safe && result.recommendedAction === 'allow') {
    return finalizeWithRotation({
      safe: true as const,
      blocked: false as const,
      action: 'allow' as const,
      agent_instruction: AGENT_INSTRUCTION_ALLOWED,
      audit: {
        scan_id: requestId,
        timestamp: new Date().toISOString(),
      },
      ...(result.sessionState ? { session_state: result.sessionState } : {}),
      ...pickGovernanceFields(result),
      ...(violations && violations.length > 0 ? { violations } : {}),
      request_id: requestId,
    }, effective_session_id);
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'prompt_injection');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return finalizeWithRotation({
    safe: false as const,
    blocked: true as const,
    action: 'block' as const,
    threat_type: threatType,
    owasp_category: OWASP_MAPPING[threatType],
    severity,
    confidence,
    guidance: getGuidance(threatType),
    agent_instruction: AGENT_INSTRUCTIONS_BLOCKED[toolName] || AGENT_INSTRUCTIONS_BLOCKED['scan_agent_card'],
    user_message: USER_MESSAGES[threatType],
    audit: {
      scan_id: requestId,
      timestamp: new Date().toISOString(),
      policy_name: 'Security Policy',
      framework_references: [OWASP_MAPPING[threatType], ...getFrameworkRefs(threatType)],
    },
    ...(result.sessionState ? { session_state: result.sessionState } : {}),
    ...pickGovernanceFields(result),
    ...(violations && violations.length > 0 ? { violations } : {}),
    request_id: requestId,
  }, effective_session_id);
}

// ============================================================================
// Internal Detail Extraction (for logging)
// ============================================================================

/**
 * Extracts internal details from scan result for logging.
 */
export function extractScanInternalDetails(
  result: InternalScanResult,
  requestId: string,
  customerId: string
): InternalLogEntry {
  return {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    customer_id: customerId,
    tool_name: 'scan_prompt',
    blocked: !result.safe || result.recommendedAction !== 'allow',
    threat_type: result.violations[0]?.threatType,
    raw_confidence: result.confidence,
    detection_layers: result.violations.map((v) => v.detectedBy),
    policy_ids: result.violations.map((v) => v.policyId),
    matched_patterns: result.violations
      .map((v) => v.matchedPattern)
      .filter((p): p is string => !!p),
    llm_analysis: result.llmAnalysis
      ? {
          confidence: result.llmAnalysis.confidence,
          reasoning: result.llmAnalysis.reasoning,
          detected_by: result.llmAnalysis.detectedBy,
        }
      : undefined,
    performance_metrics: {
      total_scan_time_ms: result.performance.totalScanTimeMs,
      policies_evaluated: result.performance.policiesEvaluated,
    },
  };
}

/**
 * Extracts internal details from specialized scan result for logging.
 */
export function extractSpecializedInternalDetails(
  result: InternalSpecializedResult,
  requestId: string,
  customerId: string,
  toolName: string
): InternalLogEntry {
  return {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    customer_id: customerId,
    tool_name: toolName,
    blocked: !result.safe || result.recommendedAction !== 'allow',
    threat_type: result.issues[0]?.type,
    raw_confidence: result.confidence,
    detection_layers: ['backend'], // Specialized scans go through backend
    policy_ids: [],
    matched_patterns: result.issues
      .map((i) => i.pattern)
      .filter((p): p is string => !!p),
    performance_metrics: {
      total_scan_time_ms: result.metadata.scanTimeMs,
      policies_evaluated: 0,
    },
  };
}
