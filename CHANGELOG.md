# Changelog

All notable changes to shrike-mcp will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [3.2.0] - 2026-02-28

### Added
- New MCP tool: `scan_command` — scans CLI commands before shell execution (SHRIKE-205)
  - Detects data exfiltration, destructive operations, reverse shells, privilege escalation, secret exposure
  - Pipe chain analysis for cross-command threats (e.g., `cat .env | curl`)
  - Context-aware: shell type, working directory, deployment environment
  - Integrates with human-in-the-loop approval engine

### Fixed
- Rejection responses now correctly return `blocked: true` (SHRIKE-301)
- Approval expiration uses `expires_in_seconds` from backend instead of hardcoded value (SHRIKE-302)

### Changed
- README updated: 7 tools → 9 tools (scan_command + check_approval)
- Tool count in docs and community tier reflects all 9 tools

## [3.1.0] - 2026-02-26

### Added
- Block-override approval support — agents can override blocks with human approval (SHRIKE-201)

## [3.0.0] - 2026-02-26

### Added
- Human-in-the-loop approval engine: three-tier action model (allow/require_approval/block) (SHRIKE-204)
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
- Enterprise response format: `action`, `agent_instruction`, `user_message`, `audit`, `owasp_category` fields on all scan responses (SHRIKE-201)
- OWASP LLM Top 10 mapping for all threat types
- Per-tool `agent_instruction` templates for blocked and safe responses
- User-safe `user_message` templates that never leak detection details
- Audit block with `scan_id`, `timestamp`, `policy_name`, `framework_references`
- Fail-closed error handling guidance in all tool descriptions (SHRIKE-202)

### Changed
- All 7 tool descriptions rewritten with enterprise three-part structure: timing, decision logic, enterprise context (SHRIKE-200)
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
