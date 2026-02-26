/**
 * scan_web_search Tool
 * Scans web search queries for security threats before execution
 *
 * ALIGNED WITH BACKEND: This tool now calls the backend's /api/scan/specialized
 * endpoint with content_type: "web_search", ensuring consistent security coverage
 * with the SDKs (Go, Python, TypeScript).
 *
 * Returns sanitized response that protects Shrike's IP while providing actionable guidance.
 */

import { config, getAuthHeaders } from '../config.js';
import {
  generateRequestId,
  sanitizeWebSearchResult,
  logInternalDetails,
  extractSpecializedInternalDetails,
  type SanitizedResponse,
} from '../utils/responseFormatter.js';

export interface WebSearchInput {
  query: string;
  targetDomains?: string[];
}

export interface WebSearchResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'block';
  issues: Array<{
    type: string;
    severity: string;
    message: string;
    pattern?: string;
  }>;
  metadata: {
    scanTimeMs: number;
    queryLength: number;
    domainsChecked: number;
  };
  approvalInfo?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
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
  approval_info?: {
    requires_approval: boolean;
    approval_id: string;
    approval_level: string;
    action_summary: string;
    policy_name: string;
    expires_in_seconds: number;
  };
}

// Blocked/suspicious domains (client-side check for speed - supplementary to backend)
const BLOCKED_DOMAINS = [
  'pastebin.com',
  'ghostbin.com',
  'hastebin.com',
  'justpaste.it',
  'paste.ee',
  'temp-mail.org',
  'guerrillamail.com',
];

// Free TLDs commonly used for malicious sites
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq',  // Freenom free TLDs
  '.xyz', '.top', '.pw', '.ws',       // Commonly abused TLDs
  '.click', '.link', '.download',     // Action-oriented TLDs
  '.zip', '.mov',                     // Confusing file extension TLDs
  '.work', '.buzz', '.site',          // Cheap/disposable TLDs
];

// Keywords in domain names that suggest malicious intent
const SUSPICIOUS_DOMAIN_KEYWORDS = [
  'malware', 'virus', 'trojan', 'exploit', 'hack', 'crack', 'keygen',
  'phish', 'scam', 'steal', 'dump', 'leak', 'breach',
  'download-free', 'free-download', 'warez', 'pirate',
];

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
function createFailClosedResponse(scanTimeMs: number, reason: string, queryLength: number, domainsChecked: number): WebSearchResult {
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
      domainsChecked,
    },
  };
}

/**
 * Scans a web search query for security issues by calling the backend API
 * This ensures consistent security coverage with the SDKs
 *
 * @param input - The web search query to scan
 * @param customerId - Customer identifier for logging (default: 'anonymous')
 * @returns Sanitized response with threat_type, confidence bucket, and guidance
 */
export async function scanWebSearch(input: WebSearchInput, customerId: string = 'anonymous'): Promise<SanitizedResponse> {
  const requestId = generateRequestId();
  const startTime = Date.now();
  const issues: WebSearchResult['issues'] = [];
  const domainsChecked = input.targetDomains?.length || 0;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    // Call backend specialized scan endpoint for web search
    // Pass targetDomains so backend can validate them too
    const response = await fetch(`${config.backendUrl}/api/scan/specialized`, {
      method: 'POST',
      headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      body: JSON.stringify({
        content: input.query,
        content_type: 'web_search',
        // Pass target domains to backend for server-side validation
        metadata: input.targetDomains?.length ? { target_domains: input.targetDomains } : undefined,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Web search scan backend returned ${response.status}`);
      const internalResult = createFailClosedResponse(Date.now() - startTime, 'Backend error', input.query.length, domainsChecked);
      if (config.debug) {
        logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_web_search'));
      } else {
        console.error(`[web] ${requestId} safe=false action=block reason=backend_error time=${Date.now() - startTime}ms`);
      }
      return sanitizeWebSearchResult(internalResult, requestId, 'scan_web_search');
    }

    const data = await response.json() as BackendSpecializedResponse;

    // Convert backend response to issues if unsafe
    if (!data.safe && data.threat_type) {
      issues.push({
        type: data.threat_type,
        severity: data.severity || 'high',
        message: data.reason || 'Security issue detected in search query',
      });
    }

    // Supplementary client-side domain checks (fast, for target domains)
    if (input.targetDomains && input.targetDomains.length > 0) {
      for (const domain of input.targetDomains) {
        const domainLower = domain.toLowerCase();

        // Check blocked domains
        if (BLOCKED_DOMAINS.some(blocked => domainLower.includes(blocked))) {
          issues.push({
            type: 'blocked_domain',
            severity: 'high',
            message: `Blocked domain: ${domain}`,
            pattern: domain,
          });
        }

        // Check suspicious TLDs
        if (SUSPICIOUS_TLDS.some(tld => domainLower.endsWith(tld))) {
          issues.push({
            type: 'suspicious_tld',
            severity: 'medium',
            message: `Suspicious TLD in domain: ${domain}`,
            pattern: domain,
          });
        }

        // Check for suspicious keywords in domain name
        if (SUSPICIOUS_DOMAIN_KEYWORDS.some(keyword => domainLower.includes(keyword))) {
          issues.push({
            type: 'suspicious_domain',
            severity: 'high',
            message: `Suspicious keyword in domain: ${domain}`,
            pattern: domain,
          });
        }
      }
    }

    // Determine overall result
    const scanTimeMs = Date.now() - startTime;
    const hasCritical = issues.some(i => i.severity === 'critical');
    const hasHigh = issues.some(i => i.severity === 'high');
    const hasMedium = issues.some(i => i.severity === 'medium');

    let threatLevel = mapSeverityToThreatLevel(data.severity);
    let recommendedAction: WebSearchResult['recommendedAction'] = data.safe ? 'allow' : mapSeverityToAction(data.severity);
    let confidence = data.confidence || 0.5;

    // Elevate threat level if domain checks found issues
    if (hasCritical) {
      threatLevel = 'critical';
      recommendedAction = 'block';
      confidence = Math.max(confidence, 0.95);
    } else if (hasHigh) {
      threatLevel = threatLevel === 'none' ? 'high' : threatLevel;
      recommendedAction = 'block';
      confidence = Math.max(confidence, 0.85);
    } else if (hasMedium && threatLevel === 'none') {
      threatLevel = 'medium';
      recommendedAction = 'flag';
      confidence = Math.max(confidence, 0.7);
    }

    const internalResult: WebSearchResult = {
      safe: data.safe && issues.length === 0,
      threatLevel,
      confidence,
      recommendedAction,
      issues,
      metadata: {
        scanTimeMs: data.scan_time_ms || scanTimeMs,
        queryLength: input.query.length,
        domainsChecked,
      },
      approvalInfo: data.approval_info,
    };

    // Log scan result
    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_web_search'));
    } else {
      console.error(`[web] ${requestId} safe=${internalResult.safe} action=${internalResult.recommendedAction} time=${Date.now() - startTime}ms`);
    }

    // Return sanitized response (protects IP)
    return sanitizeWebSearchResult(internalResult, requestId, 'scan_web_search');

  } catch (error) {
    clearTimeout(timeoutId);

    let internalResult: WebSearchResult;
    if (error instanceof Error && error.name === 'AbortError') {
      console.warn(`Web search scan timed out after ${config.scanTimeoutMs}ms, BLOCKING (fail-closed)`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Analysis timeout', input.query.length, domainsChecked);
    } else {
      console.error(`Web search scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      internalResult = createFailClosedResponse(Date.now() - startTime, 'Scan error', input.query.length, domainsChecked);
    }

    if (config.debug) {
      logInternalDetails(extractSpecializedInternalDetails(internalResult, requestId, customerId, 'scan_web_search'));
    } else {
      console.error(`[web] ${requestId} safe=false action=block reason=error time=${Date.now() - startTime}ms`);
    }
    return sanitizeWebSearchResult(internalResult, requestId, 'scan_web_search');
  }
}

/**
 * MCP Tool definition for scan_web_search
 */
export const scanWebSearchTool = {
  name: 'scan_web_search',
  description: `Call this BEFORE executing any web search query on behalf of a user or agent.

DECISION LOGIC:
- If blocked=true: do NOT execute the search. Return the user_message explaining the query was rejected.
- If blocked=false: the search query is safe to execute.

Checks for:
- PII in search queries (SSN, credit cards, API keys, private keys)
- Data exfiltration patterns (searching for leaked credentials, Google dorks)
- Blocked/suspicious domains (paste sites, suspicious TLDs)

Enterprise context: Prevents agents from inadvertently leaking internal data (names, account numbers, internal project names) through external search engines.

ERROR HANDLING: If this tool returns an error or is unavailable, default to BLOCKING the search. Do NOT send unscanned queries to external services.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'The search query to scan',
      },
      targetDomains: {
        type: 'array',
        items: { type: 'string' },
        description: 'Optional list of target domains to validate',
      },
    },
    required: ['query'],
  },
  annotations: {
    title: 'Scan Web Search',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
