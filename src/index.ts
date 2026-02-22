#!/usr/bin/env node
/**
 * Shrike MCP Server
 * AI Agent security scanning via Model Context Protocol
 * Supports stdio (default) and HTTP (Streamable HTTP) transports
 *
 * Tool Selection Modes:
 *   Mode A (Selective): SHRIKE_TOOLS=scan_prompt,scan_sql_query (env) or X-Shrike-Tools header (HTTP)
 *   Mode B (All):       Default — all 7 tools register. Backwards compatible.
 *   Mode C (Bundled):   SHRIKE_MODE=bundled — single shrike_scan tool. Minimum context footprint.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createServer as createHttpServer } from 'http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { config, logConfig, requestContext, VALID_TOOL_NAMES, type RequestContext } from './config.js';
import { validateApiKey, extractApiKey } from './auth.js';
import { rateLimiter } from './middleware/rateLimiter.js';
import { scanPrompt, scanPromptTool } from './tools/scan.js';
import { reportBypass, reportBypassTool } from './tools/reportBypass.js';
import { getThreatIntel, getThreatIntelTool } from './tools/threatIntel.js';
import { scanWebSearch, scanWebSearchTool } from './tools/webSearch.js';
import { scanSQLQuery, scanSQLQueryTool } from './tools/sqlQuery.js';
import { scanFileWrite, scanFileWriteTool } from './tools/fileWrite.js';
import { scanResponse, scanResponseTool } from './tools/scanResponse.js';
import { syncPIIPatterns } from './utils/piiSync.js';
import { createKeyProvider } from './keyProvider.js';
import { KeyRotationManager } from './keyRotation.js';

// Read version from package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf-8'));
const VERSION: string = pkg.version;

// Handle --version and --help before starting the server
const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-v')) {
  console.log(`shrike-mcp ${VERSION}`);
  process.exit(0);
}
if (args.includes('--help') || args.includes('-h')) {
  console.log(`shrike-mcp ${VERSION} — AI agent security scanning via MCP

Usage:
  npx shrike-mcp              Start MCP server (stdio transport)
  shrike-mcp --version         Print version
  shrike-mcp --help            Show this help

Environment Variables:
  SHRIKE_API_KEY               API key for authenticated scans (enables LLM layers)
  SHRIKE_BACKEND_URL           Backend API URL (default: https://api.shrikesecurity.com/agent)
  SHRIKE_TOOLS                 Comma-separated tool names to register (default: all 7)
  SHRIKE_MODE                  Tool mode: bundled (single shrike_scan tool) or omit for normal
  MCP_TRANSPORT                Transport mode: stdio (default) or http
  MCP_PORT                     HTTP server port (default: 8000, used in http mode)
  MCP_SCAN_TIMEOUT_MS          Scan timeout in ms (default: 15000)
  MCP_RATE_LIMIT_PER_MINUTE    Rate limit per customer (default: 100)
  MCP_DEBUG                    Enable debug logging (default: false)

HTTP Headers (when MCP_TRANSPORT=http):
  Authorization                Bearer <API_KEY> — per-request auth (overrides SHRIKE_API_KEY)
  X-Shrike-Tools               Comma-separated tool names (overrides SHRIKE_TOOLS)

HTTP Endpoints (when MCP_TRANSPORT=http):
  POST /mcp                    MCP Streamable HTTP endpoint (stateless)
  GET  /health                 Health check for load balancers
  GET  /.well-known/agent-card.json  Agent discovery metadata

Tools: scan_prompt, scan_response, scan_sql_query, scan_file_write,
       scan_web_search, report_bypass, get_threat_intel

Docs: https://github.com/Shrike-Security/shrike-mcp`);
  process.exit(0);
}

// Track connected customer for rate limiting (stdio mode)
let currentCustomerId: string | null = null;

// Key rotation manager — initialized in authenticate()
let keyRotationManager: KeyRotationManager | null = null;

/** Exported for 401 retry in scan tools */
export { keyRotationManager };

// =============================================================================
// TOOL REGISTRY
// =============================================================================

/** Maps tool name to its definition and handler. compact=true for JSON.stringify without indentation. */
const TOOL_REGISTRY: Record<string, {
  definition: object;
  handler: (args: any, customerId: string) => Promise<any>;
  compact?: boolean;
}> = {
  scan_prompt: {
    definition: scanPromptTool,
    handler: (a, c) => scanPrompt(a, c),
    compact: true,
  },
  scan_response: {
    definition: scanResponseTool,
    handler: (a, c) => scanResponse(a, c),
    compact: true,
  },
  scan_sql_query: {
    definition: scanSQLQueryTool,
    handler: (a, c) => scanSQLQuery(a, c),
  },
  scan_file_write: {
    definition: scanFileWriteTool,
    handler: (a, c) => scanFileWrite(a, c),
  },
  scan_web_search: {
    definition: scanWebSearchTool,
    handler: (a, c) => scanWebSearch(a, c),
  },
  report_bypass: {
    definition: reportBypassTool,
    handler: (a, _c) => reportBypass(a),
  },
  get_threat_intel: {
    definition: getThreatIntelTool,
    handler: (a, _c) => getThreatIntel(a),
  },
};

/**
 * Mode C: Single bundled tool that wraps all scan types.
 * Minimum context footprint for agents with many MCP servers.
 */
const BUNDLED_TOOL_DEFINITION = {
  name: 'shrike_scan',
  description: `Unified security scanner. Set 'type' to choose scan:
- prompt: Scan prompts for injection, PII, toxicity
- response: Scan LLM responses for data leaks
- sql_query: Detect SQL injection in queries
- file_write: Validate file writes for traversal/secrets
- web_search: Check search queries for SSRF/PII
- report_bypass: Report missed threats for community defense
- threat_intel: Get latest threat patterns`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      type: {
        type: 'string',
        enum: ['prompt', 'response', 'sql_query', 'file_write', 'web_search', 'report_bypass', 'threat_intel'],
        description: 'Scan type to perform',
      },
      input: {
        type: 'object',
        description: 'Input for the scan. For prompt: {content, context?, redact_pii?}. For sql_query: {query, database?}. For file_write: {path, content, mode?}. For web_search: {query, targetDomains?}. For response: {response, original_prompt?}. For report_bypass: {prompt?, sqlQuery?, ...}. For threat_intel: {category?, limit?}.',
        additionalProperties: true,
      },
    },
    required: ['type', 'input'],
  },
  annotations: {
    title: 'Shrike Security Scan',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

/** Maps bundled type shorthand to actual tool name */
const BUNDLED_TYPE_MAP: Record<string, string> = {
  prompt: 'scan_prompt',
  response: 'scan_response',
  sql_query: 'scan_sql_query',
  file_write: 'scan_file_write',
  web_search: 'scan_web_search',
  report_bypass: 'report_bypass',
  threat_intel: 'get_threat_intel',
};

/**
 * Resolves which tools are active based on: per-request header > env var > default.
 */
function resolveEnabledTools(headerTools?: string[] | null): string[] {
  // Per-request header takes priority (HTTP mode)
  if (headerTools && headerTools.length > 0) {
    return headerTools.filter(t => (VALID_TOOL_NAMES as readonly string[]).includes(t));
  }
  // Bundled mode: no individual tools
  if (config.mode === 'bundled') {
    return [];
  }
  // Selective mode: env var filter
  if (config.enabledTools) {
    return config.enabledTools.filter(t => (VALID_TOOL_NAMES as readonly string[]).includes(t));
  }
  // Default: all tools
  return [...VALID_TOOL_NAMES];
}

/**
 * Validates required parameters for a tool call.
 */
function validateToolArgs(name: string, args: Record<string, unknown> | undefined): void {
  switch (name) {
    case 'scan_prompt':
      if (!args?.content) throw new McpError(ErrorCode.InvalidParams, 'content is required');
      break;
    case 'scan_response':
      if (!args?.response) throw new McpError(ErrorCode.InvalidParams, 'response is required');
      break;
    case 'scan_sql_query':
      if (!args?.query) throw new McpError(ErrorCode.InvalidParams, 'query is required');
      break;
    case 'scan_file_write':
      if (!args?.path) throw new McpError(ErrorCode.InvalidParams, 'path is required');
      if (!args?.content) throw new McpError(ErrorCode.InvalidParams, 'content is required');
      break;
    case 'scan_web_search':
      if (!args?.query) throw new McpError(ErrorCode.InvalidParams, 'query is required');
      break;
    case 'report_bypass':
      if (!args?.prompt && !args?.filePath && !args?.fileContent && !args?.sqlQuery && !args?.searchQuery) {
        throw new McpError(ErrorCode.InvalidParams, 'At least one of prompt, filePath, fileContent, sqlQuery, or searchQuery is required');
      }
      break;
    // get_threat_intel has no required params
  }
}

// =============================================================================
// SERVER CREATION
// =============================================================================

interface CreateServerOptions {
  /** Per-request API key (from Authorization header in HTTP mode) */
  apiKey?: string | null;
  /** Per-request customer ID (resolved from auth) */
  customerId?: string | null;
  /** Per-request tool filter (from X-Shrike-Tools header) */
  enabledTools?: string[] | null;
}

/**
 * Creates and configures the MCP server with optional per-request overrides.
 */
function createServer(options: CreateServerOptions = {}): Server {
  const server = new Server(
    {
      name: 'shrike-mcp',
      version: VERSION,
    },
    {
      capabilities: {
        tools: {},
        prompts: {},
        resources: {},
      },
    }
  );

  // Register tool list handler — returns filtered tools based on mode + options
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    // Mode C: bundled single tool (unless per-request header overrides with specific tools)
    if (config.mode === 'bundled' && !options.enabledTools?.length) {
      return { tools: [BUNDLED_TOOL_DEFINITION] };
    }

    const enabled = resolveEnabledTools(options.enabledTools);
    const tools = enabled
      .map(name => TOOL_REGISTRY[name]?.definition)
      .filter(Boolean);

    return { tools };
  });

  // Register tool call handler — dispatches via registry
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    const effectiveCustomerId = options.customerId || currentCustomerId || 'anonymous';

    // Rate limit check
    if (effectiveCustomerId) {
      const rateLimitResult = rateLimiter.consume(effectiveCustomerId);
      if (!rateLimitResult.allowed) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          `Rate limit exceeded. Retry after ${rateLimitResult.retryAfterMs}ms`
        );
      }
    }

    try {
      // Mode C: bundled tool dispatch
      if (name === 'shrike_scan') {
        const { type, input } = (args || {}) as { type?: string; input?: Record<string, any> };
        if (!type || !input) {
          throw new McpError(ErrorCode.InvalidParams, 'type and input are required');
        }
        const actualToolName = BUNDLED_TYPE_MAP[type];
        if (!actualToolName || !TOOL_REGISTRY[actualToolName]) {
          throw new McpError(
            ErrorCode.InvalidParams,
            `Unknown scan type: ${type}. Valid types: ${Object.keys(BUNDLED_TYPE_MAP).join(', ')}`
          );
        }
        validateToolArgs(actualToolName, input);
        const entry = TOOL_REGISTRY[actualToolName];
        const result = await entry.handler(input, effectiveCustomerId);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, entry.compact ? undefined : 2) }],
        };
      }

      // Mode A/B: individual tool dispatch
      const enabled = resolveEnabledTools(options.enabledTools);
      if (!enabled.includes(name)) {
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Tool '${name}' is not enabled. Enabled tools: ${enabled.join(', ')}`
        );
      }

      const entry = TOOL_REGISTRY[name];
      if (!entry) {
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      }

      validateToolArgs(name, args as Record<string, unknown> | undefined);
      const result = await entry.handler(args, effectiveCustomerId);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, entry.compact ? undefined : 2) }],
      };
    } catch (error) {
      if (error instanceof McpError) {
        throw error;
      }
      console.error(`Tool ${name} failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw new McpError(
        ErrorCode.InternalError,
        error instanceof Error ? error.message : 'Tool execution failed'
      );
    }
  });

  // Register prompts
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    return {
      prompts: [
        {
          name: 'security-audit',
          description: 'Comprehensive security audit of user input — scans for prompt injection, PII, and toxicity, then returns a recommended action.',
          arguments: [
            {
              name: 'content',
              description: 'The text content to audit',
              required: true,
            },
          ],
        },
      ],
    };
  });

  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name } = request.params;
    if (name !== 'security-audit') {
      throw new McpError(ErrorCode.InvalidRequest, `Unknown prompt: ${name}`);
    }
    const content = request.params.arguments?.content || '';
    return {
      description: 'Security audit prompt',
      messages: [
        {
          role: 'user' as const,
          content: {
            type: 'text' as const,
            text: `Run a security audit on the following content using the scan_prompt tool. Report whether it is safe, and if not, explain the threat type, severity, and recommended action.\n\nContent to audit:\n${content}`,
          },
        },
      ],
    };
  });

  // Register resources
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: 'shrike://threat-categories',
          name: 'Threat Categories',
          description: 'List of threat categories detected by Shrike Security',
          mimeType: 'application/json',
        },
      ],
    };
  });

  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    if (uri !== 'shrike://threat-categories') {
      throw new McpError(ErrorCode.InvalidRequest, `Unknown resource: ${uri}`);
    }
    return {
      contents: [
        {
          uri,
          mimeType: 'application/json',
          text: JSON.stringify({
            categories: [
              { id: 'prompt_injection', description: 'Attempts to override system instructions or inject unauthorized commands' },
              { id: 'jailbreak', description: 'Attempts to bypass safety guardrails or content policies' },
              { id: 'pii_exposure', description: 'Personally identifiable information (SSN, credit cards, emails, phone numbers)' },
              { id: 'toxicity', description: 'Hostile, threatening, or abusive language' },
              { id: 'sql_injection', description: 'Malicious SQL patterns (UNION, stacked queries, tautologies)' },
              { id: 'secrets_exposure', description: 'API keys, passwords, tokens, private keys in content' },
              { id: 'path_traversal', description: 'Directory traversal attacks (../, system file access)' },
              { id: 'data_exfiltration', description: 'Attempts to extract sensitive data via search or output channels' },
              { id: 'system_prompt_leak', description: 'LLM revealing its system instructions in responses' },
              { id: 'topic_drift', description: 'Response diverging significantly from the original prompt intent' },
            ],
          }, null, 2),
        },
      ],
    };
  });

  return server;
}

// =============================================================================
// AGENT CARD
// =============================================================================

/**
 * Returns the agent card JSON for AgentCore / .well-known discovery.
 * Reflects the active tool set based on current configuration mode.
 */
function getAgentCard(): object {
  const enabled = resolveEnabledTools(null);
  const toolList = config.mode === 'bundled'
    ? [{ name: 'shrike_scan', description: 'Unified security scanner (bundled mode)' }]
    : enabled.map(name => {
        const entry = TOOL_REGISTRY[name];
        if (!entry) return null;
        const desc = (entry.definition as any).description;
        return { name, description: typeof desc === 'string' ? desc.split('\n')[0] : '' };
      }).filter(Boolean);

  return {
    name: 'shrike-mcp',
    version: VERSION,
    description: 'AI agent security scanner — prompt injection detection, SQL injection, PII isolation, threat intel.',
    url: `http://localhost:${config.port}/mcp`,
    transport: { type: 'streamable-http' },
    capabilities: { tools: true },
    tools: toolList,
  };
}

// =============================================================================
// AUTHENTICATION
// =============================================================================

/**
 * Authenticates the server using the configured KeyProvider.
 * Backwards compatible: default provider ('env') reads SHRIKE_API_KEY from environment.
 * In HTTP mode, per-request auth from Authorization header is also supported.
 */
async function authenticate(): Promise<void> {
  const provider = createKeyProvider();
  keyRotationManager = new KeyRotationManager(provider, {
    pollIntervalMs: config.keyPollIntervalMs,
    onKeyChanged: async (newKey: string) => {
      config.apiKey = newKey;
      try {
        const result = await validateApiKey(newKey);
        if (result.valid) {
          currentCustomerId = result.customerId || 'default';
          console.error(`[KeyRotation] Re-authenticated: ${currentCustomerId} (${result.tier})`);
        } else {
          console.error(`[KeyRotation] New key is invalid: ${result.error}`);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`[KeyRotation] Re-validation failed: ${message}`);
      }
    },
  });

  const apiKey = await keyRotationManager.initialize();
  config.apiKey = apiKey;

  if (apiKey) {
    console.error(`Validating API key from ${provider.name()} provider...`);
    const authResult = await validateApiKey(apiKey);
    if (!authResult.valid) {
      if (authResult.transient) {
        // Backend temporarily unavailable (503 during deploy, network error)
        // Continue in degraded mode instead of crashing
        console.error(`Warning: Backend temporarily unavailable (${authResult.error}). Running in degraded mode — scans will retry at request time.`);
        currentCustomerId = 'anonymous';
        return;
      }
      // Permanent auth failure (401, 403) — exit
      console.error('Invalid API key:', authResult.error);
      process.exit(1);
    }
    currentCustomerId = authResult.customerId || 'default';
    console.error(`Authenticated as customer: ${currentCustomerId} (${authResult.tier})`);
  } else {
    console.error(`No API key available (provider: ${provider.name()}), running without authentication`);
    if (config.transport === 'http') {
      console.error('  HTTP mode: clients can authenticate via Authorization header per-request');
    }
    currentCustomerId = 'anonymous';
  }
}

// =============================================================================
// TRANSPORTS
// =============================================================================

/**
 * Start in stdio mode (default — for npx, Claude Desktop, Cursor, etc.)
 */
async function startStdio(): Promise<void> {
  const server = createServer({
    apiKey: config.apiKey,
    customerId: currentCustomerId,
    enabledTools: config.enabledTools,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);

  const toolCount = config.mode === 'bundled'
    ? '1 (bundled)'
    : (config.enabledTools ? `${resolveEnabledTools(config.enabledTools).length} (selective)` : '7');
  console.error(`Shrike MCP Server running on stdio transport (${toolCount} tools)`);
}

/**
 * Start in HTTP mode (for Copilot, AWS AgentCore, GCP Cloud Run, Docker containers)
 * Stateless: creates a new Server + Transport per request (SDK recommended pattern)
 * Per-request auth: extracts Authorization header for each Copilot client
 * Per-request tools: extracts X-Shrike-Tools header for selective tool registration
 */
async function startHttp(): Promise<void> {
  const httpServer = createHttpServer(async (req, res) => {
    const url = req.url || '/';
    const method = req.method || 'GET';

    // Health check — ALB, Cloud Run, AgentCore probes
    if (url === '/health' || url === '/healthz' || url === '/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'ok',
        version: VERSION,
        service: 'shrike-mcp',
        transport: 'http',
        mode: config.mode,
        customer: currentCustomerId,
        timestamp: new Date().toISOString(),
      }));
      return;
    }

    // Agent card — AgentCore discovery
    if (url === '/.well-known/agent-card.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getAgentCard()));
      return;
    }

    // MCP endpoint — Streamable HTTP transport
    if (url === '/mcp') {
      if (method === 'POST') {
        // --- Per-request auth (US-035: Copilot sends Authorization: Bearer <key>) ---
        const authHeader = req.headers['authorization'] as string | undefined;
        const perRequestKey = extractApiKey(authHeader);

        // --- Per-request tool selection (US-034: X-Shrike-Tools header) ---
        const toolsHeader = req.headers['x-shrike-tools'] as string | undefined;
        const perRequestTools = toolsHeader
          ? toolsHeader.split(',').map(t => t.trim()).filter(Boolean)
          : null;

        // Resolve customer ID for the per-request key
        let perRequestCustomerId: string | null = null;
        if (perRequestKey) {
          const authResult = await validateApiKey(perRequestKey);
          if (authResult.valid) {
            perRequestCustomerId = authResult.customerId || 'default';
            if (config.debug) {
              console.error(`[http] Per-request auth: customer=${perRequestCustomerId} tier=${authResult.tier}`);
            }
          } else if (!authResult.transient) {
            // Permanent auth failure — reject immediately
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              error: { code: -32001, message: `Authentication failed: ${authResult.error}` },
              id: null,
            }));
            return;
          }
          // Transient failure: fall through to process-level key
        }

        // Build per-request context for AsyncLocalStorage
        const reqCtx: RequestContext = {
          apiKey: perRequestKey || config.apiKey,
          customerId: perRequestCustomerId || currentCustomerId,
          enabledTools: perRequestTools,
        };

        // Run MCP handling within AsyncLocalStorage context
        // so getAuthHeaders() in tool handlers picks up per-request key
        await requestContext.run(reqCtx, async () => {
          const server = createServer({
            apiKey: reqCtx.apiKey,
            customerId: reqCtx.customerId,
            enabledTools: reqCtx.enabledTools,
          });
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined, // Stateless — required for AgentCore
          });
          try {
            await server.connect(transport);
            await transport.handleRequest(req, res);
            res.on('close', () => {
              transport.close();
              server.close();
            });
          } catch (error) {
            console.error(`Error handling MCP request: ${error instanceof Error ? error.message : 'Unknown error'}`);
            if (!res.headersSent) {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32603, message: 'Internal server error' },
                id: null,
              }));
            }
          }
        });
        return;
      }

      // GET and DELETE not supported in stateless mode
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        error: { code: -32000, message: 'Method not allowed.' },
        id: null,
      }));
      return;
    }

    // 404 for everything else
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health', '/.well-known/agent-card.json'] }));
  });

  httpServer.listen(config.port, '0.0.0.0', () => {
    console.error(`Shrike MCP Server running on http://0.0.0.0:${config.port}`);
    console.error(`  MCP endpoint: http://0.0.0.0:${config.port}/mcp`);
    console.error(`  Health check: http://0.0.0.0:${config.port}/health`);
    console.error(`  Agent card:   http://0.0.0.0:${config.port}/.well-known/agent-card.json`);
    console.error(`  Per-request auth: Authorization: Bearer <key>`);
    console.error(`  Per-request tools: X-Shrike-Tools: scan_prompt,scan_sql_query`);
  });
}

// =============================================================================
// MAIN
// =============================================================================

/**
 * Main entry point
 */
async function main(): Promise<void> {
  console.error('Shrike MCP Server starting...');
  logConfig();

  // Validate SHRIKE_TOOLS if provided
  if (config.enabledTools) {
    const invalid = config.enabledTools.filter(t => !(VALID_TOOL_NAMES as readonly string[]).includes(t));
    if (invalid.length > 0) {
      console.error(`Warning: Unknown tool names in SHRIKE_TOOLS: ${invalid.join(', ')}`);
      console.error(`Valid tools: ${VALID_TOOL_NAMES.join(', ')}`);
    }
    const valid = config.enabledTools.filter(t => (VALID_TOOL_NAMES as readonly string[]).includes(t));
    if (valid.length === 0) {
      console.error('Error: SHRIKE_TOOLS contains no valid tool names');
      process.exit(1);
    }
    console.error(`Selective mode: ${valid.length} tools enabled: ${valid.join(', ')}`);
  }
  if (config.mode === 'bundled') {
    console.error('Bundled mode: single "shrike_scan" tool registered');
  }

  await authenticate();
  await syncPIIPatterns();

  // Heartbeat logging (for monitoring)
  const heartbeatInterval = setInterval(() => {
    if (config.debug) {
      console.error(`[heartbeat] active, customer=${currentCustomerId}, transport=${config.transport}, mode=${config.mode}`);
    }
  }, config.heartbeatIntervalMs);

  // Handle shutdown
  process.on('SIGINT', () => {
    clearInterval(heartbeatInterval);
    keyRotationManager?.stop();
    console.error('Shutting down...');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    clearInterval(heartbeatInterval);
    keyRotationManager?.stop();
    console.error('Shutting down...');
    process.exit(0);
  });

  if (config.transport === 'http') {
    await startHttp();
  } else {
    await startStdio();
  }
}

main().catch((error) => {
  console.error(`Fatal error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  process.exit(1);
});
