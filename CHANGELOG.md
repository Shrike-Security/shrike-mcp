# Changelog

All notable changes to shrike-mcp will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-02-19

First stable release. Signals production readiness — v1.x was the pre-release development cycle.

### Added
- Full 9-layer detection pipeline on all tiers (including community)
- Community tier: 10K scans/month, all 7 tools, full L1–L8 pipeline, no credit card
- README rewritten for product launch (quick start, tools table, pipeline overview, client configs)
- MCP client config examples for Claude Desktop, Cursor, and Windsurf
- CHANGELOG.md (this file)

### Changed
- Community/free tier upgraded from L1–L4 (regex only) to full L1–L8 pipeline
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
- 9-layer detection pipeline (L1 regex through L8 response intelligence)
- PII isolation with token-based rehydration
- Response obfuscation for IP protection
- Fail-closed security model
- Apache 2.0 license
