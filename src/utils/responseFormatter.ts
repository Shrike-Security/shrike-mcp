/**
 * Response Formatter for IP Protection
 *
 * Sanitizes MCP server responses to protect Shrike's intellectual property
 * by removing internal detection layer details while preserving actionable
 * guidance for users.
 *
 * Internal details are logged to stderr for debugging (not exposed to clients).
 */

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * Threat types exposed to external clients (normalized from internal types)
 */
export type ThreatType =
  | 'prompt_injection'
  | 'jailbreak'
  | 'system_prompt_leak'
  | 'data_exfiltration'
  | 'sql_injection'
  | 'path_traversal'
  | 'secrets_exposure'
  | 'pii_exposure'
  | 'blocked_domain'
  | 'toxicity'
  | 'malicious_code'
  | 'harmful_intent'
  | 'social_engineering'
  | 'privilege_escalation'
  | 'destructive_operation'
  | 'scan_error'
  | 'size_limit_exceeded'
  | 'unknown';

/**
 * Confidence bucket levels (replaces raw 0.0-1.0 scores)
 */
export type ConfidenceBucket = 'high' | 'medium' | 'low';

/**
 * Severity levels
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Sanitized response for blocked/flagged threats (external-facing)
 */
export interface SanitizedBlockedResponse {
  blocked: true;
  threat_type: ThreatType;
  severity: Severity;
  confidence: ConfidenceBucket;
  guidance: string;
  request_id: string;
}

/**
 * Sanitized response for allowed requests (external-facing)
 */
export interface SanitizedAllowedResponse {
  blocked: false;
  request_id: string;
}

/**
 * Union type for all sanitized responses
 */
export type SanitizedResponse = SanitizedBlockedResponse | SanitizedAllowedResponse;

/**
 * Internal log entry structure (for server-side debugging)
 */
export interface InternalLogEntry {
  request_id: string;
  timestamp: string;
  customer_id: string;
  tool_name: string;
  blocked: boolean;
  threat_type?: string;
  raw_confidence?: number;
  detection_layers: string[];
  policy_ids: string[];
  matched_patterns: string[];
  llm_analysis?: {
    confidence: number;
    reasoning: string;
    detected_by: string;
  };
  performance_metrics?: {
    total_scan_time_ms: number;
    policies_evaluated: number;
  };
}

// ============================================================================
// Guidance Map
// ============================================================================

/**
 * User-friendly guidance text for each threat type.
 * Explains what was detected WITHOUT revealing how it was detected.
 */
const THREAT_GUIDANCE: Record<ThreatType, string> = {
  prompt_injection:
    'This prompt contains patterns consistent with instruction override attempts. Review the source content for embedded commands.',
  jailbreak:
    'This prompt attempts to bypass safety guidelines. The request has been blocked.',
  system_prompt_leak:
    'The LLM response contains system prompt or internal configuration disclosure, indicating a successful jailbreak. The response has been blocked.',
  data_exfiltration:
    'This prompt may attempt to extract sensitive information. Review for PII or credential exposure patterns.',
  sql_injection:
    'This query contains potentially dangerous SQL patterns. Review for unauthorized data access or modification attempts.',
  path_traversal:
    'This file path attempts to access directories outside the allowed scope. Review for directory traversal patterns.',
  secrets_exposure:
    'This content contains patterns matching API keys, tokens, or credentials. Avoid committing secrets to files.',
  pii_exposure:
    'This content contains personally identifiable information. Consider redacting before processing.',
  blocked_domain:
    'This web search targets a restricted domain. Review your organization\'s acceptable use policy.',
  toxicity:
    'This content contains potentially harmful or inappropriate language. Review before proceeding.',
  malicious_code:
    'This content contains patterns associated with malicious code such as reverse shells, web shells, or persistence mechanisms. The file has been blocked.',
  harmful_intent:
    'This request contains content associated with harmful or dangerous intent. The request has been blocked.',
  social_engineering:
    'This prompt contains social engineering patterns such as authority claims, urgency pressure, or trust manipulation.',
  privilege_escalation:
    'This query attempts to escalate privileges, modify user roles, or gain unauthorized access.',
  destructive_operation:
    'This query contains destructive operations such as DROP TABLE, TRUNCATE, or mass DELETE. Review carefully before executing.',
  scan_error:
    'The security scan could not be completed. The request has been blocked as a precaution.',
  size_limit_exceeded:
    'The content exceeds the maximum allowed size. Please reduce the content size and retry.',
  unknown:
    'A security concern was detected. Please review the content and retry.',
};

// ============================================================================
// Core Utility Functions
// ============================================================================

/**
 * Generates a unique request ID for traceability.
 * Format: req_<timestamp_base36>_<random_8chars>
 */
export function generateRequestId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `req_${timestamp}_${random}`;
}

/**
 * Converts numeric confidence (0.0-1.0) to bucketed level.
 * Protects IP by not exposing exact thresholds.
 */
export function bucketConfidence(score: number): ConfidenceBucket {
  if (score >= 0.9) return 'high';
  if (score >= 0.7) return 'medium';
  return 'low';
}

/**
 * Maps internal threat types to normalized external types.
 * Normalizes the variety of internal threat type names to a consistent set.
 */
export function normalizeThreatType(internalType: string): ThreatType {
  const normalized = internalType.toLowerCase().replace(/[_-]/g, '_');

  const mapping: Record<string, ThreatType> = {
    // Prompt injection variants (from LLM intent and categories)
    prompt_injection: 'prompt_injection',
    injection: 'prompt_injection',
    inject: 'prompt_injection',      // LLM intent: INJECT
    instruction_override: 'prompt_injection',
    role_hijacking: 'prompt_injection',
    context_manipulation: 'prompt_injection',
    token_manipulation: 'prompt_injection',   // LLM category: spaced chars, l33t speak
    indirect_injection: 'prompt_injection',   // Document parser: hidden text attacks
    context_poisoning: 'prompt_injection',    // Multi-turn attacks
    function_injection: 'prompt_injection',   // Tool/function injection
    memory_injection: 'prompt_injection',     // False memory attacks

    // Jailbreak variants (from LLM analyzer categories)
    jailbreak: 'jailbreak',
    jailbreak_attempt: 'jailbreak',
    safety_bypass: 'jailbreak',
    roleplay: 'jailbreak',           // LLM category: roleplay attacks (DAN, etc.)
    hypothetical: 'jailbreak',       // LLM category: hypothetical/academic framing
    social_engineering: 'social_engineering', // LLM category: authority/urgency manipulation
    completion_baiting: 'jailbreak', // LLM category: continue harmful content
    emotional: 'social_engineering',  // LLM category: emotional manipulation
    override: 'jailbreak',           // LLM intent: OVERRIDE
    manipulate: 'jailbreak',         // LLM intent: MANIPULATE
    toxicity: 'toxicity',
    harmful_content: 'toxicity',

    // Data exfiltration (from LLM intent and categories)
    data_exfiltration: 'data_exfiltration',
    exfiltration: 'data_exfiltration',
    exfiltrate: 'data_exfiltration', // LLM intent: EXFILTRATE
    extract: 'data_exfiltration',    // LLM intent: EXTRACT
    data_leak: 'data_exfiltration',
    information_disclosure: 'data_exfiltration',
    system_prompt_extraction: 'system_prompt_leak',  // Reveal system prompt
    system_prompt_leak: 'system_prompt_leak',        // L8 Response Intelligence: system prompt leaked in response
    credential_extraction: 'data_exfiltration',

    // L8 Response Intelligence anomaly types
    unexpected_pii_leakage: 'pii_exposure',         // L8: PII in response not in prompt
    tonality_drift_profanity: 'jailbreak',          // L8: profanity in response (jailbreak indicator)
    tonality_drift_casual: 'jailbreak',             // L8: casual tone (persona adoption)
    tonality_drift_hostile: 'jailbreak',            // L8: hostile language (jailbreak indicator)
    topic_mismatch: 'prompt_injection',             // L8: response topic differs from prompt

    // SQL injection
    sql_injection: 'sql_injection',
    sqli: 'sql_injection',
    tautology: 'sql_injection',
    tautology_or: 'sql_injection',
    tautology_and: 'sql_injection',
    union_injection: 'sql_injection',
    stacked_query: 'sql_injection',

    // Path traversal
    path_traversal: 'path_traversal',
    directory_traversal: 'path_traversal',
    path_violation: 'path_traversal',
    file_access: 'path_traversal',
    sensitive_path: 'path_traversal',

    // Secrets (from backend path_validator.go)
    secrets_exposure: 'secrets_exposure',
    secrets: 'secrets_exposure',
    api_key: 'secrets_exposure',
    credential: 'secrets_exposure',
    sensitive_file: 'secrets_exposure',
    content_violation: 'secrets_exposure',
    sensitive_content: 'secrets_exposure',  // Backend sends this for secrets
    secret_key: 'secrets_exposure',
    aws_key: 'secrets_exposure',
    private_key: 'secrets_exposure',

    // PII (from LLM pii_extraction category and path_validator)
    pii_exposure: 'pii_exposure',
    pii: 'pii_exposure',
    pii_leak: 'pii_exposure',
    personal_data: 'pii_exposure',
    pii_in_search: 'pii_exposure',
    pii_extraction: 'pii_exposure',  // LLM category: PII extraction attempts
    ssn: 'pii_exposure',
    credit_card: 'pii_exposure',
    email_exposure: 'pii_exposure',
    phone_number: 'pii_exposure',
    health_record: 'pii_exposure',   // PHI/HIPAA
    medical_data: 'pii_exposure',
    patient_data: 'pii_exposure',

    // Domain blocking
    blocked_domain: 'blocked_domain',
    suspicious_tld: 'blocked_domain',
    suspicious_domain: 'blocked_domain',  // Domains with malicious keywords
    malicious_url: 'blocked_domain',

    // Malicious code (shells, miners, etc.) - maps to standard "malicious_code"
    malicious_content: 'malicious_code',  // Backend path_validator type
    malicious_code: 'malicious_code',     // Standard category
    reverse_shell: 'malicious_code',
    web_shell: 'malicious_code',
    fork_bomb: 'malicious_code',
    crypto_miner: 'malicious_code',
    persistence: 'malicious_code',
    shell_injection: 'malicious_code',

    // Harmful intent
    harmful_intent: 'harmful_intent',
    dangerous_request: 'harmful_intent',

    // Social engineering (additional mappings)
    authority_claim: 'social_engineering',

    // Privilege escalation (from SQL detector)
    privilege_escalation: 'privilege_escalation',

    // Destructive operations (from SQL detector)
    destructive_operation: 'destructive_operation',

    // Path/extension blocking
    sensitive_extension: 'path_traversal',  // Blocked file extension → path category
    blocked_extension: 'path_traversal',

    // Errors
    scan_error: 'scan_error',
    size_limit_exceeded: 'size_limit_exceeded',
    size_limit: 'size_limit_exceeded',
    timeout: 'scan_error',
  };

  return mapping[normalized] || 'unknown';
}

/**
 * Gets guidance text for a threat type.
 */
export function getGuidance(threatType: ThreatType): string {
  return THREAT_GUIDANCE[threatType] || THREAT_GUIDANCE.unknown;
}

/**
 * Determines the highest severity from a list.
 */
export function getHighestSeverity(severities: string[]): Severity {
  const order: Severity[] = ['critical', 'high', 'medium', 'low'];
  for (const level of order) {
    if (severities.some((s) => s.toLowerCase() === level)) {
      return level;
    }
  }
  return 'medium';
}

// ============================================================================
// Internal Logging
// ============================================================================

/**
 * Logs full internal details to stderr for debugging.
 * This preserves all IP-sensitive information server-side.
 *
 * Uses stderr to avoid interfering with MCP JSON-RPC on stdout.
 */
export function logInternalDetails(entry: InternalLogEntry): void {
  const logEntry = {
    level: 'info',
    type: 'scan_detail',
    ...entry,
  };

  // Use console.error (stderr) to avoid interfering with MCP protocol on stdout
  console.error(JSON.stringify(logEntry));
}

// ============================================================================
// Sanitization Functions for Each Tool Type
// ============================================================================

/**
 * Internal result type from scan.ts (for type safety)
 */
interface InternalScanResult {
  safe: boolean;
  threatLevel: string;
  confidence: number;
  recommendedAction: 'allow' | 'flag' | 'redact' | 'block';
  violations: Array<{
    threatType: string;
    severity: string;
    confidence: number;
    action: string;
    detectedBy: string;
    message: string;
    policyId: string;
    policyName: string;
    scanStage?: string;
    matchedPattern?: string;
  }>;
  llmAnalysis?: {
    analyzed: boolean;
    isMalicious: boolean;
    confidence: number;
    threatType: string;
    reasoning: string;
    detectedBy: string;
    analysisTimeMs: number;
  };
  performance: {
    totalScanTimeMs: number;
    policiesEvaluated: number;
    llmAnalysisUsed: boolean;
    cacheHits: number;
  };
}

/**
 * Internal result type from specialized scans (SQL, file, web)
 */
interface InternalSpecializedResult {
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
    location?: string;
  }>;
  metadata: {
    scanTimeMs: number;
    [key: string]: unknown;
  };
}

/**
 * Sanitizes scan_prompt result.
 * Removes: detectedBy, policyId, matchedPattern, llmAnalysis details
 * Buckets: confidence scores
 * Adds: guidance text
 */
export function sanitizeScanResult(
  result: InternalScanResult,
  requestId: string
): SanitizedResponse {
  // Safe results get minimal response
  // Note: PII redaction returns safe=true with recommendedAction='redact' — this is NOT a block
  if (result.safe && (result.recommendedAction === 'allow' || result.recommendedAction === 'redact')) {
    return {
      blocked: false,
      request_id: requestId,
    };
  }

  // Get primary threat from violations
  const primaryViolation = result.violations[0];
  const threatType = normalizeThreatType(primaryViolation?.threatType || 'unknown');
  const severity = getHighestSeverity(
    result.violations.map((v) => v.severity)
  );
  const confidence = bucketConfidence(result.confidence);

  return {
    blocked: true,
    threat_type: threatType,
    severity,
    confidence,
    guidance: getGuidance(threatType),
    request_id: requestId,
  };
}

/**
 * Sanitizes scan_sql_query result.
 */
export function sanitizeSQLResult(
  result: InternalSpecializedResult,
  requestId: string
): SanitizedResponse {
  if (result.safe && result.recommendedAction === 'allow') {
    return {
      blocked: false,
      request_id: requestId,
    };
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'sql_injection');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return {
    blocked: true,
    threat_type: threatType,
    severity,
    confidence,
    guidance: getGuidance(threatType),
    request_id: requestId,
  };
}

/**
 * Sanitizes scan_file_write result.
 */
export function sanitizeFileWriteResult(
  result: InternalSpecializedResult,
  requestId: string
): SanitizedResponse {
  if (result.safe && result.recommendedAction === 'allow') {
    return {
      blocked: false,
      request_id: requestId,
    };
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'unknown');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return {
    blocked: true,
    threat_type: threatType,
    severity,
    confidence,
    guidance: getGuidance(threatType),
    request_id: requestId,
  };
}

/**
 * Sanitizes scan_web_search result.
 */
export function sanitizeWebSearchResult(
  result: InternalSpecializedResult,
  requestId: string
): SanitizedResponse {
  if (result.safe && result.recommendedAction === 'allow') {
    return {
      blocked: false,
      request_id: requestId,
    };
  }

  const primaryIssue = result.issues[0];
  const threatType = normalizeThreatType(primaryIssue?.type || 'blocked_domain');
  const severity = getHighestSeverity(result.issues.map((i) => i.severity));
  const confidence = bucketConfidence(result.confidence);

  return {
    blocked: true,
    threat_type: threatType,
    severity,
    confidence,
    guidance: getGuidance(threatType),
    request_id: requestId,
  };
}

// ============================================================================
// Internal Detail Extraction (for logging)
// ============================================================================

/**
 * Extracts internal details from scan result for logging.
 */
export function extractScanInternalDetails(
  result: InternalScanResult,
  requestId: string,
  customerId: string
): InternalLogEntry {
  return {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    customer_id: customerId,
    tool_name: 'scan_prompt',
    blocked: !result.safe || result.recommendedAction !== 'allow',
    threat_type: result.violations[0]?.threatType,
    raw_confidence: result.confidence,
    detection_layers: result.violations.map((v) => v.detectedBy),
    policy_ids: result.violations.map((v) => v.policyId),
    matched_patterns: result.violations
      .map((v) => v.matchedPattern)
      .filter((p): p is string => !!p),
    llm_analysis: result.llmAnalysis
      ? {
          confidence: result.llmAnalysis.confidence,
          reasoning: result.llmAnalysis.reasoning,
          detected_by: result.llmAnalysis.detectedBy,
        }
      : undefined,
    performance_metrics: {
      total_scan_time_ms: result.performance.totalScanTimeMs,
      policies_evaluated: result.performance.policiesEvaluated,
    },
  };
}

/**
 * Extracts internal details from specialized scan result for logging.
 */
export function extractSpecializedInternalDetails(
  result: InternalSpecializedResult,
  requestId: string,
  customerId: string,
  toolName: string
): InternalLogEntry {
  return {
    request_id: requestId,
    timestamp: new Date().toISOString(),
    customer_id: customerId,
    tool_name: toolName,
    blocked: !result.safe || result.recommendedAction !== 'allow',
    threat_type: result.issues[0]?.type,
    raw_confidence: result.confidence,
    detection_layers: ['backend'], // Specialized scans go through backend
    policy_ids: [],
    matched_patterns: result.issues
      .map((i) => i.pattern)
      .filter((p): p is string => !!p),
    performance_metrics: {
      total_scan_time_ms: result.metadata.scanTimeMs,
      policies_evaluated: 0,
    },
  };
}
