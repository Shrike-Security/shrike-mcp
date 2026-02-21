/**
 * MCP Server Configuration
 * Loads settings from environment variables with sensible defaults
 */

import { AsyncLocalStorage } from 'node:async_hooks';

/**
 * Per-request context for HTTP transport.
 * Allows each Copilot/HTTP request to carry its own API key and tool filter
 * without modifying individual tool handler files.
 */
export interface RequestContext {
  apiKey: string | null;
  customerId: string | null;
  enabledTools: string[] | null;
}

/** AsyncLocalStorage for per-request context (HTTP mode). */
export const requestContext = new AsyncLocalStorage<RequestContext>();

export interface Config {
  /** Transport mode: 'stdio' (default) or 'http' */
  transport: 'stdio' | 'http';
  /** HTTP server port (used when transport is 'http') */
  port: number;
  /** Backend API URL for scan requests */
  backendUrl: string;
  /** Shrike API key for authenticated (paid tier) scans */
  apiKey: string | null;
  /** Timeout for scan requests in milliseconds */
  scanTimeoutMs: number;
  /** Rate limit: requests per minute per API key */
  rateLimitPerMinute: number;
  /** Heartbeat interval in milliseconds */
  heartbeatIntervalMs: number;
  /** Enable debug logging */
  debug: boolean;
  /** Tool registration mode: 'all' (default), 'selective', or 'bundled' */
  mode: 'all' | 'selective' | 'bundled';
  /** Enabled tools (used when mode is 'selective'). Null means all. */
  enabledTools: string[] | null;
}

function getEnvOrDefault(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

function getEnvNumber(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

export const config: Config = {
  transport: (process.env.MCP_TRANSPORT === 'http' ? 'http' : 'stdio') as 'stdio' | 'http',
  port: getEnvNumber('MCP_PORT', 8000),
  // Default uses load balancer for scalability. Override with SHRIKE_BACKEND_URL for VPC deployments.
  backendUrl: getEnvOrDefault('SHRIKE_BACKEND_URL', 'https://api.shrikesecurity.com/agent'),
  // API key for authenticated scans (enables LLM layer L7-L8)
  // Without API key, scans are free tier (L1-L4 regex only)
  // Get your API key at: https://console.shrikesecurity.com/api-keys
  apiKey: process.env.SHRIKE_API_KEY || null,
  // SECURITY: 15000ms allows for full 8-layer scan pipeline with LLM analysis
  // Backend takes ~10s for comprehensive scans including vector embeddings + LLM
  scanTimeoutMs: getEnvNumber('MCP_SCAN_TIMEOUT_MS', 15000),
  rateLimitPerMinute: getEnvNumber('MCP_RATE_LIMIT_PER_MINUTE', 100),
  heartbeatIntervalMs: getEnvNumber('MCP_HEARTBEAT_INTERVAL_MS', 30000),
  debug: getEnvOrDefault('MCP_DEBUG', 'false') === 'true',
  // Tool selection: SHRIKE_MODE=bundled → single shrike_scan tool
  //                 SHRIKE_TOOLS=scan_prompt,scan_sql_query → selective mode
  //                 Neither set → all 7 tools (backwards compatible)
  mode: (() => {
    if (process.env.SHRIKE_MODE?.toLowerCase() === 'bundled') return 'bundled' as const;
    if (process.env.SHRIKE_TOOLS) return 'selective' as const;
    return 'all' as const;
  })(),
  enabledTools: process.env.SHRIKE_TOOLS
    ? process.env.SHRIKE_TOOLS.split(',').map(t => t.trim()).filter(Boolean)
    : null,
};

export function logConfig(): void {
  // Use stderr to avoid interfering with MCP JSON-RPC protocol on stdout
  console.error('MCP Server Configuration:');
  console.error(`  Transport: ${config.transport}`);
  console.error(`  Port: ${config.port} ${config.transport === 'stdio' ? '(unused in stdio mode)' : ''}`);
  console.error(`  Backend URL: ${config.backendUrl}`);
  console.error(`  API Key: ${config.apiKey ? '***' + config.apiKey.slice(-4) + ' (authenticated - L1-L8 full scan)' : 'NOT SET (free tier - L1-L4 regex only)'}`);
  console.error(`  Scan Timeout: ${config.scanTimeoutMs}ms`);
  console.error(`  Rate Limit: ${config.rateLimitPerMinute} req/min`);
  console.error(`  Mode: ${config.mode}`);
  console.error(`  Enabled Tools: ${config.enabledTools ? config.enabledTools.join(', ') : 'all'}`);
  console.error(`  Debug: ${config.debug}`);
}

/**
 * Returns authorization headers for backend requests.
 * In HTTP mode, per-request key from AsyncLocalStorage takes priority
 * over the process-level SHRIKE_API_KEY. This lets each Copilot user
 * send their own API key without modifying tool handler files.
 */
export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const ctx = requestContext.getStore();
  const key = ctx?.apiKey ?? config.apiKey;
  if (key) {
    headers['Authorization'] = `Bearer ${key}`;
  }
  return headers;
}

/** All valid tool names that can be used with SHRIKE_TOOLS */
export const VALID_TOOL_NAMES = [
  'scan_prompt', 'scan_response', 'scan_sql_query',
  'scan_file_write', 'scan_web_search', 'report_bypass', 'get_threat_intel',
] as const;

export type ValidToolName = typeof VALID_TOOL_NAMES[number];
