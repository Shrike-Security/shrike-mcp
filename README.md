# shrike-mcp

MCP (Model Context Protocol) server for Shrike Security — protect AI agents from prompt injection, jailbreaks, SQL injection, data exfiltration, and malicious file operations.

## Installation

```bash
npm install -g shrike-mcp
```

Or use with npx:

```bash
npx shrike-mcp
```

## Quick Start

### With Claude Desktop

Add to your Claude Desktop configuration (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "shrike-security": {
      "command": "npx",
      "args": ["shrike-mcp"],
      "env": {
        "SHRIKE_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Without an API key, scans run on the free tier (regex-only layers L1–L4). With an API key, you get the full 9-layer scan pipeline including LLM semantic analysis.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHRIKE_API_KEY` | API key for authenticated scans (enables L7/L8 LLM layers) | *none* (free tier) |
| `SHRIKE_BACKEND_URL` | URL of the Shrike backend API | `https://api.shrikesecurity.com/agent` |
| `MCP_SCAN_TIMEOUT_MS` | Timeout for scan requests (ms) | `15000` |
| `MCP_RATE_LIMIT_PER_MINUTE` | Max requests per minute per customer | `100` |
| `MCP_TRANSPORT` | Transport mode: `stdio` (default) or `http` | `stdio` |
| `MCP_PORT` | HTTP server port (used when `MCP_TRANSPORT=http`) | `8000` |
| `MCP_DEBUG` | Enable debug logging (`true`/`false`) | `false` |

## Available Tools

### `scan_prompt`

Scans user prompts for prompt injection, jailbreak attempts, and malicious content. Supports PII redaction with token-based rehydration.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `content` | string | Yes | The prompt text to scan |
| `context` | string | No | Conversation history for context-aware scanning |
| `redact_pii` | boolean | No | When true, PII is redacted before scanning. Response includes tokens for rehydration. |

**Example:**

```typescript
const result = await mcp.callTool('scan_prompt', {
  content: userInput,
  context: conversationHistory,
  redact_pii: true,
});

if (result.blocked) {
  console.log('Threat detected:', result.threat_type);
} else if (result.pii_redaction) {
  // Use redacted content for LLM processing
  const safePrompt = result.pii_redaction.redacted_content;
}
```

### `scan_response`

Scans LLM-generated responses before showing them to users. Detects system prompt leaks, unexpected PII, toxic language, and topic drift. Rehydrates PII tokens when provided.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response` | string | Yes | The LLM-generated response to scan |
| `original_prompt` | string | No | The original prompt (enables PII diff and topic mismatch detection) |
| `pii_tokens` | array | No | PII token map from `scan_prompt(redact_pii=true)` for rehydration |

**Example:**

```typescript
const result = await mcp.callTool('scan_response', {
  response: llmOutput,
  original_prompt: userInput,
  pii_tokens: scanPromptResult.pii_redaction?.tokens,
});

if (result.blocked) {
  console.log('Response blocked:', result.threat_type);
} else if (result.rehydrated_response) {
  // PII tokens replaced with original values
  showToUser(result.rehydrated_response);
}
```

### `scan_sql_query`

Scans SQL queries for injection attacks and dangerous operations before execution.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | The SQL query to scan |
| `database` | string | No | Target database name for context |
| `allowDestructive` | boolean | No | Allow DROP/TRUNCATE for migrations (default: false) |

**Example:**

```typescript
const result = await mcp.callTool('scan_sql_query', {
  query: sqlQuery,
  database: 'postgresql',
});

if (result.blocked) {
  throw new Error(`SQL injection detected: ${result.guidance}`);
}
```

### `scan_file_write`

Validates file paths and content before write operations. Checks for path traversal, secrets in content, and sensitive file access.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | The target file path |
| `content` | string | Yes | The content to write |
| `mode` | string | No | Write mode: `create`, `overwrite`, or `append` |

**Example:**

```typescript
const result = await mcp.callTool('scan_file_write', {
  path: filePath,
  content: fileContent,
  mode: 'create',
});

if (result.blocked) {
  throw new Error(`File write blocked: ${result.guidance}`);
}
```

### `scan_web_search`

Scans web search queries for PII exposure, data exfiltration patterns, and blocked domains.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | The search query to scan |
| `targetDomains` | string[] | No | List of target domains to validate |

**Example:**

```typescript
const result = await mcp.callTool('scan_web_search', {
  query: searchQuery,
  targetDomains: ['example.com'],
});

if (result.blocked) {
  console.log('Search blocked:', result.guidance);
}
```

### `report_bypass`

Reports content that bypassed security checks to improve detection via ThreatSense pattern learning.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `prompt` | string | No | The prompt that bypassed detection |
| `filePath` | string | No | File path for file_write bypasses |
| `fileContent` | string | No | File content that should have been blocked |
| `sqlQuery` | string | No | SQL query that bypassed injection detection |
| `searchQuery` | string | No | Web search query with undetected PII |
| `mutationType` | string | No | Type of mutation used (e.g., `semantic_rewrite`, `encoding_exploit`) |
| `category` | string | No | Threat category (auto-inferred if not provided) |
| `notes` | string | No | Additional notes about the bypass |

### `get_threat_intel`

Retrieves current threat intelligence including active detection patterns, threat categories, and statistics.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | No | Filter by threat category |
| `limit` | number | No | Max patterns to return (default: 50) |

## Response Format

All scan tools return a sanitized response:

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

Safe results return:

```json
{
  "blocked": false,
  "request_id": "req_lxyz123_a8f3k2m9"
}
```

## Security Model

This MCP server implements a **fail-closed** security model:

- Network timeouts result in **BLOCK** (not allow)
- Backend errors result in **BLOCK** (not allow)
- Unknown content types result in **BLOCK** (not allow)

This prevents bypass attacks via service disruption.

## Known Limitations

1. **Free tier is regex-only** — No LLM semantic analysis without API key
2. **No offline mode** — Requires network access to Shrike backend
3. **Response Intelligence requires original prompt** — `original_prompt` param is optional but recommended for full L8 analysis
4. **Rate limits are MCP-side only** — Backend has separate per-tier limits
5. **HTTP transport is stateless** — Each request creates a new server instance; no session persistence across requests

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

## Support

- GitHub Issues: https://github.com/Shrike-Security/shrike-mcp/issues
- Email: support@shrikesecurity.com

## Changelog

### v1.1.0 (February 12, 2026)
- Dual transport: stdio (default) + HTTP (Streamable HTTP)
- SDK upgrade to `@modelcontextprotocol/sdk@1.26.0`
- Published to [MCP Registry](https://registry.modelcontextprotocol.io)
- Health check, agent card, and Docker support for cloud deployments

### v1.0.0 (February 10, 2026)
- Initial public release
- 7 MCP tools for AI agent security
- 9-layer detection pipeline
- PII isolation with token rehydration
- Response obfuscation for IP protection

## Links

- [GitHub Repository](https://github.com/Shrike-Security/shrike-mcp)
- [npm Package](https://www.npmjs.com/package/shrike-mcp)
- [MCP Registry](https://registry.modelcontextprotocol.io/servers/io.github.Shrike-Security/shrike-mcp)
- [Issue Tracker](https://github.com/Shrike-Security/shrike-mcp/issues)
