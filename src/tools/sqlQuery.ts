/**
 * scan_sql_query Tool
 * Scans SQL queries for injection attacks and dangerous operations
 *
 * ALIGNED WITH BACKEND: This tool now calls the backend's /scan/specialized
 * endpoint instead of using local regex, ensuring consistent security coverage
 * with the SDKs (Go, Python, TypeScript).
 *
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance.
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeSQLResult,
  logInternalDetails,
  extractSpecializedInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';

export interface SQLQueryInput {
  query: string;
  database?: string;
  allowDestructive?: boolean;
}

export interface SQLQueryResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'block';
  issues: Array<{
    type: string;
    severity: string;
    message: string;
    pattern?: string;
    position?: number;
  }>;
  metadata: {
    scanTimeMs: number;
    queryLength: number;
    statementType: string;
  };
}

/**
 * Backend specialized scan response type
 */
interface BackendSpecializedResponse {
  safe: boolean;
  threat_type?: string;
  severity?: string;
  reason?: string;
  confidence: number;
  content_type: string;
  scan_time_ms: number;
}

/**
 * Determines the type of SQL statement
 */
function getStatementType(query: string): string {
  const normalized = query.trim().toUpperCase();
  if (normalized.startsWith('SELECT')) return 'SELECT';
  if (normalized.startsWith('INSERT')) return 'INSERT';
  if (normalized.startsWith('UPDATE')) return 'UPDATE';
  if (normalized.startsWith('DELETE')) return 'DELETE';
  if (normalized.startsWith('DROP')) return 'DROP';
  if (normalized.startsWith('CREATE')) return 'CREATE';
  if (normalized.startsWith('ALTER')) return 'ALTER';
  if (normalized.startsWith('TRUNCATE')) return 'TRUNCATE';
  if (normalized.startsWith('GRANT')) return 'GRANT';
  if (normalized.startsWith('REVOKE')) return 'REVOKE';
  return 'UNKNOWN';
}

/**
 * Maps severity to threat level
 */
function mapSeverityToThreatLevel(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'none';
  }
}

/**
 * Maps severity to recommended action
 */
function mapSeverityToAction(severity: string | undefined): 'allow' | 'flag' | 'block' {
  switch (severity?.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'block';
    case 'medium':
      return 'flag';
    default:
      return 'allow';
  }
}

/**
 * Creates a fail-closed response when scanning fails
 * SECURITY: Timeouts and errors are treated as unsafe to prevent bypasses
 */
function createFailClosedResponse(scanTimeMs: number, reason: string, queryLength: number, statementType: string): SQLQueryResult {
  return {
    safe: false,
    threatLevel: 'high',
    confidence: 1.0,
    recommendedAction: 'block',
    issues: [{
      type: 'scan_error',
      severity: 'high',
      message: `Security scan could not complete: ${reason}. Blocking as precaution.`,
    }],
    metadata: {
      scanTimeMs,
      queryLength,
      statementType,
    },
  };
}

/**
 * Scans a SQL query for security issues by calling the backend API
 * This ensures consistent security coverage with the SDKs
 *
 * @param input - The SQL query to scan
 * @param customerId - Customer identifier for logging (default: 'anonymous')
 * @returns Sanitized response with threat_type, confidence bucket, and guidance
 */
export async function scanSQLQuery(input: SQLQueryInput, customerId: string = 'anonymous'): Promise<SanitizedResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  const statementType = getStatementType(input.query);
  const queryLength = input.query.length;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    // Build context for backend
    const context: Record<string, string> = {};
    if (input.database) {
      context.database = input.database;
    }
    if (input.allowDestructive) {
      context.allow_destructive = 'true';
    }

    // Call backend specialized scan endpoint (note: /api prefix required)
    const response = await fetch(`${config.backendUrl}/api/scan/specialized`, {
      method: 'POST',
      headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      body: JSON.stringify({
        content: input.query,
        content_type: 'sql',
        context: Object.keys(context).length > 0 ? context : undefined,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`SQL scan backend returned ${response.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', queryLength, statementType);
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_sql_query'));
      return sanitizeSQLResult(internalResult, requestId);
    }

    const data = await response.json() as BackendSpecializedResponse;
    const scanTimeMs = Date.now() - startTime;

    // Transform backend response to internal format
    const issues: SQLQueryResult['issues'] = [];
    if (!data.safe && data.threat_type) {
      issues.push({
        type: data.threat_type,
        severity: data.severity || 'high',
        message: data.reason || 'SQL security issue detected',
      });
    }

    const internalResult: SQLQueryResult = {
      safe: data.safe,
      threatLevel: mapSeverityToThreatLevel(data.severity),
      confidence: data.confidence,
      recommendedAction: data.safe ? 'allow' : mapSeverityToAction(data.severity),
      issues,
      metadata: {
        scanTimeMs: data.scan_time_ms || scanTimeMs,
        queryLength,
        statementType,
      },
    };

    // Log full internal details for debugging (not exposed to client)
    logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_sql_query'));

    // Return sanitized response (protects IP)
    return sanitizeSQLResult(internalResult, requestId);

  } catch (error) {
    clearTimeout(timeoutId);

    let internalResult: SQLQueryResult;
    if (error instanceof Error && error.name === 'AbortError') {
      console.warn(`SQL scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Analysis timeout', queryLength, statementType);
    } else {
      console.error('SQL scan failed:', error);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Scan error', queryLength, statementType);
    }

    logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_sql_query'));
    return sanitizeSQLResult(internalResult, requestId);
  }
}

/**
 * MCP Tool definition for scan_sql_query
 */
export const scanSQLQueryTool = {
  name: 'scan_sql_query',
  description: `Scans a SQL query before execution for security threats.

Checks for:
- SQL injection patterns (UNION, stacked queries, tautologies, blind injection)
- Destructive operations (DROP, TRUNCATE, DELETE without WHERE)
- Privilege escalation (GRANT, CREATE USER)
- PII extraction (queries on password/SSN/credit card columns)

Set allowDestructive=true to permit DROP/TRUNCATE for migrations.

Returns:
- blocked: true/false
- threat_type: sql_injection, etc.
- severity: critical/high/medium/low
- confidence: high/medium/low
- guidance: actionable explanation
- request_id: unique identifier`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'The SQL query to scan',
      },
      database: {
        type: 'string',
        description: 'Optional target database name for context',
      },
      allowDestructive: {
        type: 'boolean',
        description: 'Allow destructive operations like DROP/TRUNCATE (default: false)',
      },
    },
    required: ['query'],
  },
};
