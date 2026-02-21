#!/usr/bin/env node
/**
 * Shrike MCP Server
 * AI Agent security scanning via Model Context Protocol
 * Supports stdio (default) and HTTP (Streamable HTTP) transports
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

import { config, logConfig } from './config.js';
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
  MCP_TRANSPORT                Transport mode: stdio (default) or http
  MCP_PORT                     HTTP server port (default: 8000, used in http mode)
  MCP_SCAN_TIMEOUT_MS          Scan timeout in ms (default: 15000)
  MCP_RATE_LIMIT_PER_MINUTE    Rate limit per customer (default: 100)
  MCP_DEBUG                    Enable debug logging (default: false)

HTTP Endpoints (when MCP_TRANSPORT=http):
  POST /mcp                    MCP Streamable HTTP endpoint (stateless)
  GET  /health                 Health check for load balancers
  GET  /.well-known/agent-card.json  Agent discovery metadata

Tools: scan_prompt, scan_response, scan_sql_query, scan_file_write,
       scan_web_search, report_bypass, get_threat_intel

Docs: https://github.com/Shrike-Security/shrike-mcp`);
  process.exit(0);
}

// Track connected customer for rate limiting
let currentCustomerId: string | null = null;

/**
 * Creates and configures the MCP server
 */
function createServer(): Server {
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

  // Register tool list handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        scanPromptTool,
        reportBypassTool,
        getThreatIntelTool,
        scanWebSearchTool,
        scanSQLQueryTool,
        scanFileWriteTool,
        scanResponseTool,
      ],
    };
  });

  // Register tool call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // Rate limit check
    if (currentCustomerId) {
      const rateLimitResult = rateLimiter.consume(currentCustomerId);
      if (!rateLimitResult.allowed) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          `Rate limit exceeded. Retry after ${rateLimitResult.retryAfterMs}ms`
        );
      }
    }

    try {
      switch (name) {
        case 'scan_prompt': {
          const input = args as { content: string; context?: string; redact_pii?: boolean };
          if (!input.content) {
            throw new McpError(ErrorCode.InvalidParams, 'content is required');
          }
          const result = await scanPrompt(input, currentCustomerId || 'anonymous');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result),
              },
            ],
          };
        }

        case 'report_bypass': {
          const input = args as {
            prompt?: string;
            filePath?: string;
            fileContent?: string;
            sqlQuery?: string;
            searchQuery?: string;
            mutationType?: string;
            category?: string;
            notes?: string;
          };
          if (!input.prompt && !input.filePath && !input.fileContent && !input.sqlQuery && !input.searchQuery) {
            throw new McpError(ErrorCode.InvalidParams, 'At least one of prompt, filePath, fileContent, sqlQuery, or searchQuery is required');
          }
          const result = await reportBypass(input);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        case 'get_threat_intel': {
          const input = args as { category?: string; limit?: number };
          const result = await getThreatIntel(input);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        case 'scan_web_search': {
          const input = args as { query: string; targetDomains?: string[] };
          if (!input.query) {
            throw new McpError(ErrorCode.InvalidParams, 'query is required');
          }
          const result = await scanWebSearch(input, currentCustomerId || 'anonymous');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result),
              },
            ],
          };
        }

        case 'scan_sql_query': {
          const input = args as { query: string; database?: string; allowDestructive?: boolean };
          if (!input.query) {
            throw new McpError(ErrorCode.InvalidParams, 'query is required');
          }
          const result = await scanSQLQuery(input, currentCustomerId || 'anonymous');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result),
              },
            ],
          };
        }

        case 'scan_file_write': {
          const input = args as { path: string; content: string; mode?: 'create' | 'overwrite' | 'append' };
          if (!input.path) {
            throw new McpError(ErrorCode.InvalidParams, 'path is required');
          }
          if (!input.content) {
            throw new McpError(ErrorCode.InvalidParams, 'content is required');
          }
          const result = await scanFileWrite(input, currentCustomerId || 'anonymous');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result),
              },
            ],
          };
        }

        case 'scan_response': {
          const input = args as {
            response: string;
            original_prompt?: string;
            pii_tokens?: Array<{ token: string; original: string; type: string }>;
          };
          if (!input.response) {
            throw new McpError(ErrorCode.InvalidParams, 'response is required');
          }
          const result = await scanResponse(input, currentCustomerId || 'anonymous');
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result),
              },
            ],
          };
        }

        default:
          throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
      }
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

/**
 * Returns the agent card JSON for AgentCore / .well-known discovery
 */
function getAgentCard(): object {
  return {
    name: 'shrike-mcp',
    version: VERSION,
    description: 'AI agent security scanner — prompt injection detection, SQL injection, PII isolation, threat intel.',
    url: `http://localhost:${config.port}/mcp`,
    transport: { type: 'streamable-http' },
    capabilities: { tools: true },
    tools: [
      { name: 'scan_prompt', description: 'Scan user prompts for injection attacks and adversarial inputs' },
      { name: 'scan_response', description: 'Scan LLM responses for data leaks and manipulation' },
      { name: 'scan_sql_query', description: 'Detect SQL injection in AI-generated queries' },
      { name: 'scan_file_write', description: 'Validate file write operations for path traversal and malicious content' },
      { name: 'scan_web_search', description: 'Check search queries for SSRF and domain abuse' },
      { name: 'report_bypass', description: 'Report novel attack patterns for community defense' },
      { name: 'get_threat_intel', description: 'Retrieve latest threat patterns and detection signatures' },
    ],
  };
}

/**
 * Authenticates the server using SHRIKE_API_KEY from environment
 */
async function authenticate(): Promise<void> {
  const apiKey = process.env.SHRIKE_API_KEY;
  if (apiKey) {
    console.error('Validating API key...');
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
    console.error('No SHRIKE_API_KEY set, running without authentication');
    currentCustomerId = 'anonymous';
  }
}

/**
 * Start in stdio mode (default — for npx, Claude Desktop, Cursor, etc.)
 */
async function startStdio(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Shrike MCP Server running on stdio transport');
}

/**
 * Start in HTTP mode (for AWS AgentCore, GCP Cloud Run, Docker containers)
 * Stateless: creates a new Server + Transport per request (SDK recommended pattern)
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
        const server = createServer();
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
  });
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  console.error('Shrike MCP Server starting...');
  logConfig();

  await authenticate();
  await syncPIIPatterns();

  // Heartbeat logging (for monitoring)
  const heartbeatInterval = setInterval(() => {
    if (config.debug) {
      console.error(`[heartbeat] active, customer=${currentCustomerId}, transport=${config.transport}`);
    }
  }, config.heartbeatIntervalMs);

  // Handle shutdown
  process.on('SIGINT', () => {
    clearInterval(heartbeatInterval);
    console.error('Shutting down...');
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    clearInterval(heartbeatInterval);
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
