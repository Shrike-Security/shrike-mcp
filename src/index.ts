#!/usr/bin/env node
/**
 * Shrike MCP Server
 * AI Agent security scanning via Model Context Protocol (stdio transport)
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
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
  MCP_SCAN_TIMEOUT_MS          Scan timeout in ms (default: 15000)
  MCP_RATE_LIMIT_PER_MINUTE    Rate limit per customer (default: 100)
  MCP_DEBUG                    Enable debug logging (default: false)

Tools: scan_prompt, scan_response, scan_sql_query, scan_file_write,
       scan_web_search, report_bypass, get_threat_intel

Docs: https://github.com/shrike-security/shrike-security-agent`);
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
            prompt: string;
            mutationType?: string;
            category?: string;
            notes?: string;
          };
          if (!input.prompt) {
            throw new McpError(ErrorCode.InvalidParams, 'prompt is required');
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
      console.error(`Tool ${name} failed:`, error);
      throw new McpError(
        ErrorCode.InternalError,
        error instanceof Error ? error.message : 'Tool execution failed'
      );
    }
  });

  return server;
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  // Use stderr for all logging to avoid interfering with MCP JSON-RPC on stdout
  console.error('Shrike MCP Server starting...');
  logConfig();

  // Check for API key in environment (for stdio transport)
  const apiKey = process.env.SHRIKE_API_KEY;
  if (apiKey) {
    console.error('Validating API key...');
    const authResult = await validateApiKey(apiKey);
    if (!authResult.valid) {
      console.error('Invalid API key:', authResult.error);
      process.exit(1);
    }
    currentCustomerId = authResult.customerId || 'default';
    console.error(`Authenticated as customer: ${currentCustomerId} (${authResult.tier})`);
  } else {
    console.error('No SHRIKE_API_KEY set, running without authentication');
    currentCustomerId = 'anonymous';
  }

  const server = createServer();

  // Use stdio transport (standard for MCP)
  const transport = new StdioServerTransport();

  // Heartbeat logging (for monitoring)
  const heartbeatInterval = setInterval(() => {
    if (config.debug) {
      console.error(`[heartbeat] active, customer=${currentCustomerId}`);
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

  // Connect and run
  await server.connect(transport);
  console.error('Shrike MCP Server running on stdio transport');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
