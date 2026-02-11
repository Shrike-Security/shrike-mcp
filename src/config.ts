/**
 * MCP Server Configuration
 * Loads settings from environment variables with sensible defaults
 */

export interface Config {
  /** MCP server port */
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
  port: getEnvNumber('MCP_PORT', 3000),
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
};

export function logConfig(): void {
  // Use stderr to avoid interfering with MCP JSON-RPC protocol on stdout
  console.error('MCP Server Configuration:');
  console.error(`  Port: ${config.port}`);
  console.error(`  Backend URL: ${config.backendUrl}`);
  console.error(`  API Key: ${config.apiKey ? '***' + config.apiKey.slice(-4) + ' (authenticated - L1-L8 full scan)' : 'NOT SET (free tier - L1-L4 regex only)'}`);
  console.error(`  Scan Timeout: ${config.scanTimeoutMs}ms`);
  console.error(`  Rate Limit: ${config.rateLimitPerMinute} req/min`);
  console.error(`  Heartbeat Interval: ${config.heartbeatIntervalMs}ms`);
  console.error(`  Debug: ${config.debug}`);
}

/**
 * Returns authorization headers if API key is configured
 */
export function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (config.apiKey) {
    headers['Authorization'] = `Bearer ${config.apiKey}`;
  }
  return headers;
}
