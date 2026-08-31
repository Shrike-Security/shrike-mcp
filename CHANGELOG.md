# Changelog

All notable changes to shrike-mcp will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [4.0.2] - 2026-08-31

### Changed
- **Discoverability keywords.** Added `mcp-server`, `modelcontextprotocol`, and `cline` to the npm keywords so the package surfaces in MCP registry and directory search. Metadata-only.

### Fixed
- **Clarified npm-only distribution.** An unrelated third-party package holds the name `shrike-mcp` on PyPI, so a user guessing `pip install shrike-mcp` would install the wrong package. The Quick Start now states the server is npm-only (`npx shrike-mcp`, Node.js required) and points Python *code* integration at the Python SDK (`pip install shrike-guard`). Documentation-only.

## [4.0.1] - 2026-07-16

### Fixed
- Corrected the tool-count line in the 4.0.0 entry below. The shipped surface is **14 tools** (matches `package.json` and the README); the `12 → 11` line recorded only the `get_threat_intel` removal and was never updated after later 4.0.x tools (`scanDeclareScope`, `scanResponse`, `scanMCPSchema`) were added.
- Reconciled release dating: the 4.0.0 changes were prepared 2026-07-03 and published to npm on 2026-07-16.

## [4.0.0] - 2026-07-03

### Removed (BREAKING)
- **Removed `get_threat_intel` tool.** The tool exposed dashboard-oriented content (pattern lists, ThreatSense learning stats, per-category coverage) to the agent's `tools/list`, where it neither informed nor changed agent decisions in real workflows. Pattern review and threat intelligence oversight belong on the Shrike dashboard, not in the agent-facing MCP surface.
  - **Migration:** agents that previously invoked `get_threat_intel` for session self-inspection should read `sessionStats` fields carried in future scan responses (per the session-state extension in the roadmap). Human threat-intel review is available on the Shrike dashboard admin surface.
  - Tool count with this removal: 12 → 11. (Later 4.0.x tools bring the shipped total to **14** — see the 4.0.1 note above and the README.)

### Added
- **Automatic client-side SESSION_ID rotation on high-risk / quarantine.** When a scan response arrives with `threat_type: session_locked` or `session_state.session_risk_score` at/above a configurable threshold, the MCP client emits a `client_session_rotation` record on the triggering response. The record has two shapes depending on session ownership:

  **Module-owned** (caller did NOT supply `session_id` on the tool call — MCP's fallback SESSION_ID was in use):

  ```json
  "client_session_rotation": {
    "rotated": true,
    "owner": "mcp_client",
    "reason": "session_locked" | "risk_threshold_exceeded",
    "previous_session_id": "old-uuid",
    "new_session_id": "new-uuid",
    "triggering_risk_score": 0.85,
    "configured_threshold": 0.7
  }
  ```

  MCP mutates its module SESSION_ID in place. Subsequent calls that don't supply their own session_id land on the fresh session.

  **Caller-owned** (caller supplied `session_id` on the tool call — session lifecycle belongs to the caller):

  ```json
  "client_session_rotation": {
    "rotated": false,
    "rotation_recommended": true,
    "owner": "caller",
    "reason": "session_locked" | "risk_threshold_exceeded",
    "current_session_id": "<caller's supplied id, echoed back>",
    "suggested_new_session_id": "<fresh UUID>",
    "triggering_risk_score": 0.85,
    "configured_threshold": 0.7
  }
  ```

  MCP does **not** mutate anything in this branch — the caller decides whether to adopt `suggested_new_session_id`, mint their own, or ignore the recommendation. `current_session_id` is echoed back exactly as supplied so the integrator can correlate the rotation event with their own session bookkeeping.

  - **Verdict trigger** (safety net): fires on `threat_type: "session_locked"`. Opt out via `SHRIKE_ROTATE_ON_LOCK=false`.
  - **Score trigger** (customer knob): fires when `session_state.session_risk_score >= SHRIKE_ROTATION_THRESHOLD` (default `0.7`). Set the env var to any value `> 1.0` (e.g. `"2"`) to disable this trigger.
  - **`AGENT_ID` stays stable across rotations by design.** Rotation is a conversation-boundary reset, not an identity reset — same-agent continuity is what the correlator uses to detect "N rapid rotations from one agent" as an attacker rate-limit signal. Erasing agent_id on rotation would kill that observability.
  - Emits a stderr log line for observability: `[session-rotation] owner=<mcp_client|caller> reason=... score=<n> threshold=<n>`.

  **Change from earlier 4.0.0 pre-release:** the first cut of this feature always mutated the module SESSION_ID and always reported `previous_session_id` / `new_session_id` — even when the caller had supplied their own `session_id`. That created a namespace mismatch: the caller received rotation events referencing UUIDs it never used, and the module-side mutation had no effect on the caller's next call. The two-shape record above resolves it: MCP only mutates state it owns, and signals a recommendation for state the caller owns.
- **`session_locked` threat type mapping.** When the Shrike backend flags an entire session as high-risk (accumulated multi-turn correlation above threshold), it emits a `session_locked` verdict. Prior client releases treated this as an unrecognized type and displayed the generic guidance message. This release recognizes the verdict and surfaces the intended session-quarantine guidance ("start a fresh session to continue") to the caller. Requires the shrikesecurity.com backend as of July 2026 or a compatible self-hosted deployment.
- Backend-owned PII prefix contract for `syncPIIPatterns()` — the recognizer owns its entity tag rather than the client maintaining an allowlist. No pattern is ever silently dropped for an unmapped prefix.
- **Symmetric `session_state` block on every scan response.** Every scan response — allowed and blocked, observe-plane and act-plane — now carries a top-level `session_state` block whenever the caller supplied `session_id` or `agent_id`. Shape:

  ```json
  "session_state": {
    "session_risk_score": 0.42,
    "session_turn_number": 5,
    "session_patterns": ["multi_turn_escalation"]
  }
  ```

  - `session_risk_score` — 0.0–1.0, rounded to 2 decimal places. Outcome-shaped signal, not attribution. An adversary observing the score cannot determine which internal detector fired.
  - `session_turn_number` — 1-indexed within the session.
  - `session_patterns` — canonical `multi_turn_*` threat-type strings drawn from the same taxonomy already exposed on `violations[].threat_type`. Empty array (not omitted) when no patterns matched, so integrator loops can rely on the field's shape.

  The block is **symmetric**: it appears on the very first (benign) turn, climbs through allowed responses as risk accumulates, and remains present when a `session_locked` block finally lands. Integrators watching the trajectory can pull an agent back on their side (auto-rotate, escalate, cross-agent supervision) before Shrike has to enforce. The block is absent only when the caller supplied no session identity — signalling "session-less scan" cleanly rather than misrepresenting it as `turn_number: 0` with no risk.

  The `SessionState` type is exported from `shrike-mcp` for TypeScript integrators. Available on `SanitizedBlockedResponse`, `SanitizedAllowedResponse`, AND `SanitizedApprovalResponse` as an optional `session_state` field. Requires the shrikesecurity.com backend as of July 2026.

### Fixed — symmetric contract follow-ups (post-first-verification, same 4.0.0 pre-release window)

- **`session_state` now populates on `require_approval` responses.** The initial 4.0.0 cut only threaded the block through the allow and block sanitizer branches; the third response type (`require_approval`) omitted it. This broke `if (response.session_state.session_risk_score > threshold)` integrator policies on the response branch most likely to hit elevated risk — precisely the response that block-override approvals produce during a poisoning trajectory. Fixed by threading `sessionState` through `buildApprovalResponse` and passing it from every sanitizer call site. Regression guard: parameterized approval-branch tests in `sessionState.test.ts`.
- **`session_patterns` is now gated on anomaly detection (backend contract change).** Prior behavior: the correlator's internal pattern matchers (e.g. `multi_turn_reconnaissance`, tuned on turn-count and velocity) fire on benign multi-turn trajectories that stay well below the anomaly threshold, and the initial `ToSessionState()` projection emitted every matched category regardless of whether the risk score justified it. That surfaced labels like `multi_turn_reconnaissance` on 4-turn benign chats at `session_risk_score: 0.3` — creating three concrete misinterpretation risks:
  1. The agent may self-throttle unnecessarily (Cooperative Governance working against a legitimate task).
  2. Customer policies keyed on the pattern string fire on innocent sessions.
  3. Any UI rendering the label reads it as an accusation on benign behavior.

  New behavior: below `AnomalyDetected` (`session_risk_score < 0.5`, the same gate the correlator already uses internally to decide whether to inject session violations), `session_patterns` is an empty array. `session_turn_number` and `session_risk_score` — neutral scalars — still ship on every response so integrators can threshold. The customer contract is now consistent with the internal one: Shrike is only willing to stand behind a labeled pattern once the score has crossed the threshold. Regression guard: `TestToSessionState_PatternsSuppressedBelowAnomaly` + `TestToSessionState_PatternsEmittedAtAnomaly` in `common/correlation/session_state_test.go`.

### Removed (BREAKING) — audit-block session fields
- `audit.session_risk_score` and `audit.correlation_patterns` are **removed** from the sanitized wire response. They previously lived nested inside the compliance audit block; the new top-level `session_state` block is the customer contract for operational governance. Integrators reading `response.audit.session_risk_score` must switch to `response.session_state.session_risk_score`. The audit block retains only compliance-oriented fields (`scan_id`, `timestamp`, `policy_name`, `framework_references`).

### Fixed
- **Caller-supplied `session_id` / `agent_id` are now honored.** Every tool's schema advertises `session_id`, `agent_id`, `parent_agent_id`, and `task_chain` as caller-controllable parameters. In prior builds those inputs were silently overwritten by the MCP client's process-level defaults at the request-body construction site — the schema's contract was cosmetic and integrators observed no scoping effect from varying the parameters. This release reverses the precedence: caller-supplied values win, and the process-level `getSessionId()` / `getAgentId()` are used only as fallbacks. The server-managed `source_application` remains client-controlled for integrity. Applies to all eight scan tools (`scan_prompt`, `scan_response`, `scan_command`, `scan_sql_query`, `scan_file_write`, `scan_web_search`, `scan_a2a_message`, `scan_agent_card`).

### Changed
- **Governance-plane classification is now a structured extension field on every scan tool.** Each tool declares its plane via the MCP `_meta` extension slot at the tool root:

  ```
  _meta: {
    "shrike/scan_class": "observe" | "act",
    "shrike/quarantine_gated": boolean,
    "shrike/contract_version": "2026-07-03",
  }
  ```

  Integrators can classify a tool's quarantine semantics from the tool schema without parsing English.

  - Observe plane (`scan_prompt`, `scan_response`): `shrike/scan_class="observe"`, `shrike/quarantine_gated=false`. These tools remain available and return real verdicts even when the session is quarantined; content analysis has no side effects, and visibility into what an agent is being asked to process stays valuable.
  - Act plane (`scan_command`, `scan_sql_query`, `scan_file_write`, `scan_web_search`, `scan_a2a_message`, `scan_agent_card`): `shrike/scan_class="act"`, `shrike/quarantine_gated=true`. These tools return `threat_type: "session_locked"` when the session's accumulated risk crosses the quarantine threshold, refusing to authorize side effects.

  Fields are placed on `_meta` (MCP's explicit extension slot, `z.ZodRecord(z.ZodUnknown)`) rather than `annotations`, because `ToolAnnotationsSchema` is a closed Zod object using `$strip` mode and silently drops any field not in the schema at `tools/list` serialization. `_meta` preserves arbitrary keys through the wire. Keys are namespaced with the `shrike/` prefix to avoid collisions with other extensions.
- **Tool descriptions rewritten** to reflect the observe/act plane split. Prior descriptions carried the same "SESSION QUARANTINE: session will be blocked" paragraph on all eight tools, including the two content scanners that never lock — creating the misleading impression that quarantine behavior was uniform. The two observe-plane descriptions now state explicitly that they remain available during quarantine; the six act-plane descriptions retain the quarantine notice with a recovery path pointing at session rotation (and a reference to the observe plane for continued visibility).
- **Contract test** at `plane_classification.test.ts` pins the intended classification with two independent assertions per tool: a static read from the tool export, and an SDK-wire test that parses the tool through `ToolSchema` to confirm the plane fields survive serialization. The wire test is the check that would have caught the initial-attempt SDK-strip bug before ship.

### Rationale
MCP tools serve the agent's next decision. Dashboard serves human oversight. `get_threat_intel` mixed both purposes and served neither well — the stats block always read as `activePatterns: 0, totalDetections: 0` for fresh customers (because ThreatSense learning starts empty), giving the false impression the product wasn't working, while the pattern list was noise for an LLM trying to decide "should I proceed?"

## [3.3.0] - 2026-02-28

### Security
- Agent self-approval bypass prevention
  - High/critical approvals now require dashboard authentication (JWT) — MCP-submitted decisions are rejected with `DASHBOARD_REQUIRED`
  - 60-second cooldown on low/medium MCP-submitted decisions — prevents instant agent self-approval (`COOLDOWN_ACTIVE`)
  - Self-approval blocked — the entity that triggered a scan cannot approve its own request (`SELF_APPROVAL_BLOCKED`)
  - Scanner service `/decide` route removed — decisions only available via dashboard (`SCANNER_ROUTE_DENIED`)
  - `check_approval` tool updated with structured 403 error handling and user-facing guidance for all enforcement scenarios

## [3.2.0] - 2026-02-28

### Added
- New MCP tool: `scan_command` — scans CLI commands before shell execution
  - Detects data exfiltration, destructive operations, reverse shells, privilege escalation, secret exposure
  - Pipe chain analysis for cross-command threats (e.g., `cat .env | curl`)
  - Context-aware: shell type, working directory, deployment environment
  - Integrates with human-in-the-loop approval engine

### Fixed
- Rejection responses now correctly return `blocked: true`
- Approval expiration uses `expires_in_seconds` from backend instead of hardcoded value

### Changed
- README updated: 7 tools → 9 tools (scan_command + check_approval)
- Tool count in docs and community tier reflects all 9 tools

## [3.1.0] - 2026-02-26

### Added
- Block-override approval support — agents can override blocks with human approval

## [3.0.0] - 2026-02-26

### Added
- Human-in-the-loop approval engine: three-tier action model (allow/require_approval/block)
- New MCP tool: `check_approval` — poll approval status and submit decisions
- New response action: `require_approval` with `approval_id`, `approval_context`, and polling instructions
- Approval policies: configurable per-org rules for when human approval is required
- Approval API: create, decide, status, list, pending, stats, cancel endpoints
- Expiration: auto-expire pending approvals after configurable timeout (default 30 min)
- Webhook notifications: approval_created, approval_expiring, approval_decided, approval_expired events
- Content-hash dedup: prevents duplicate approval requests for the same action

### Changed
- `SanitizedResponse` union type now includes `SanitizedApprovalResponse`
- Tool count: 7 → 8 (added check_approval)
- `blocked: true` for require_approval responses ensures agents that only check `blocked` will safely halt

## [2.2.0] - 2026-02-26

### Added
- Enterprise response format: `action`, `agent_instruction`, `user_message`, `audit`, `owasp_category` fields on all scan responses
- OWASP LLM Top 10 mapping for all threat types
- Per-tool `agent_instruction` templates for blocked and safe responses
- User-safe `user_message` templates that never leak detection details
- Audit block with `scan_id`, `timestamp`, `policy_name`, `framework_references`
- Fail-closed error handling guidance in all tool descriptions

### Changed
- All 7 tool descriptions rewritten with enterprise three-part structure: timing, decision logic, enterprise context
- `report_bypass` description uses 3 concrete invocation triggers instead of vague "suspect"
- `scan_sql_query` description differentiates read vs write query risk
- `scan_file_write` description explicitly covers read operations (path traversal)
- `get_threat_intel` description includes caching guidance (1 hour)
- Existing fields (`blocked`, `threat_type`, `severity`, `confidence`, `guidance`, `request_id`) preserved for backward compatibility

## [2.1.1] - 2026-02-26

### Changed
- `get_threat_intel` upgraded: returns server version, stats (detections, cost savings, learning queue), coverage across 10 attack categories, and `include` param for summary vs full detail
- Categories expanded from 4 to 10 (added multilingual, semantic_rewrite, negation_attack, command_injection, healthcare_harm, financial_crime)

## [2.1.0] - 2026-02-26

### Added
- Vault-based key management with pluggable KeyProvider (env, file, vault, aws, gcp)
- Configurable tool selection via `SHRIKE_TOOLS` env var or `X-Shrike-Tools` header
- Per-request Copilot auth via `Authorization` header in HTTP mode

### Fixed
- Strip Go `(?i)` flag from synced PII patterns before JS RegExp
- Retry on 5xx during startup auth (don't crash on transient errors)
- Community tier updated from 10K to 1K scans/month

### Changed
- README cleaned up — removed implementation details from detection pipeline description

## [2.0.0] - 2026-02-19

First stable release. Signals production readiness — v1.x was the pre-release development cycle.

### Added
- Full detection pipeline on all tiers (including community)
- Community tier: 1K scans/month, all 7 tools, full pipeline, no credit card
- README rewritten for product launch (quick start, tools table, pipeline overview, client configs)
- MCP client config examples for Claude Desktop, Cursor, and Windsurf
- CHANGELOG.md (this file)

### Changed
- Community/free tier upgraded from regex-only to full multi-stage pipeline
- package.json metadata updated (description, keywords, homepage)
- README restructured: hero line, badges, 3-step quick start, 7-tool table, scan-sandwich diagram

## [1.1.5] - 2026-02-18

### Fixed
- Minor stability improvements

## [1.1.0] - 2026-02-12

### Added
- Dual transport: stdio (default) + HTTP (Streamable HTTP)
- Health check endpoint (`GET /health`)
- Agent card discovery (`GET /.well-known/agent-card.json`)
- Docker support with multi-stage build
- MCP Registry and Smithery integration configs

### Changed
- SDK upgraded to `@modelcontextprotocol/sdk@1.26.0`

## [1.0.0] - 2026-02-10

### Added
- Initial public release
- 7 MCP tools: scan_prompt, scan_response, scan_sql_query, scan_file_write, scan_web_search, report_bypass, get_threat_intel
- Multi-stage detection pipeline (pattern matching through response intelligence)
- PII isolation with token-based rehydration
- Response obfuscation for IP protection
- Fail-closed security model
- Apache 2.0 license
