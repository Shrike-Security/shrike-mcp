/**
 * PII Redactor - Client-side PII redaction and rehydration for MCP
 *
 * Detects PII in text, replaces with indexed tokens, and provides
 * a reversible map for rehydration after LLM processing.
 *
 * PII never leaves the MCP process — neither the backend nor the LLM sees raw PII.
 */

export interface PIIPattern {
  name: string;
  regex: RegExp;
  prefix: string; // e.g. "EMAIL" → [EMAIL_1], [EMAIL_2]
}

export interface RedactionEntry {
  token: string;     // [EMAIL_1]
  original: string;  // john@acme.com
  type: string;      // email
  position: number;  // char offset in original text
}

export interface RedactionResult {
  redactedText: string;
  redactions: RedactionEntry[];
  piiDetected: boolean;
  redactionCount: number;
}

/**
 * PII patterns matching the backend's PIISanitizer patterns.
 * Order matters: more specific patterns first to avoid partial matches.
 */
const PII_PATTERNS: PIIPattern[] = [
  // AWS keys (very specific, check first)
  {
    name: 'aws_key',
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    prefix: 'AWSKEY',
  },
  // Private keys
  {
    name: 'private_key',
    regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
    prefix: 'PRIVKEY',
  },
  // Credit card numbers (Visa, MC, Amex, Discover)
  {
    name: 'credit_card',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    prefix: 'CARD',
  },
  // SSN (US)
  {
    name: 'ssn',
    regex: /\b\d{3}-?\d{2}-?\d{4}\b/g,
    prefix: 'SSN',
  },
  // Email addresses
  {
    name: 'email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    prefix: 'EMAIL',
  },
  // Phone numbers (US/International)
  {
    name: 'phone',
    regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    prefix: 'PHONE',
  },
  // API keys (generic pattern)
  {
    name: 'api_key',
    regex: /\b(?:api[_-]?key|apikey|access[_-]?token)[:\s=]+[A-Za-z0-9_\-]{20,}\b/gi,
    prefix: 'APIKEY',
  },
  // Medical record numbers
  {
    name: 'medical_record',
    regex: /\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b/gi,
    prefix: 'MRN',
  },
  // Date of birth
  {
    name: 'dob',
    regex: /\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date)[:\s]+(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b/gi,
    prefix: 'DOB',
  },
  // Bank account numbers
  {
    name: 'bank_account',
    regex: /\b(?:Account|Acct)[:\s#]*\d{8,17}\b/gi,
    prefix: 'ACCOUNT',
  },
  // Routing numbers (US - 9 digits)
  {
    name: 'routing_number',
    regex: /\b(?:Routing|ABA)[:\s#]*\d{9}\b/gi,
    prefix: 'ROUTING',
  },
  // IP addresses
  {
    name: 'ip_address',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    prefix: 'IP',
  },
  // Street addresses (simple pattern)
  {
    name: 'address',
    regex: /\b\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b/gi,
    prefix: 'ADDR',
  },
];

/**
 * Redacts PII from text, replacing with indexed tokens.
 *
 * Example:
 *   Input:  "Email john@acme.com and jane@acme.com about the meeting"
 *   Output: "Email [EMAIL_1] and [EMAIL_2] about the meeting"
 *   Map:    { "[EMAIL_1]": "john@acme.com", "[EMAIL_2]": "jane@acme.com" }
 */
export function redactPII(text: string): RedactionResult {
  const redactions: RedactionEntry[] = [];
  const counters: Record<string, number> = {};
  let redactedText = text;

  // Collect all matches across all patterns with their positions
  const allMatches: Array<{
    start: number;
    end: number;
    original: string;
    pattern: PIIPattern;
  }> = [];

  for (const pattern of PII_PATTERNS) {
    // Reset regex lastIndex for global patterns
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.regex.exec(text)) !== null) {
      allMatches.push({
        start: match.index,
        end: match.index + match[0].length,
        original: match[0],
        pattern,
      });
    }
  }

  // Sort ascending by position for deduplication and token numbering
  allMatches.sort((a, b) => a.start - b.start);

  // Deduplicate overlapping matches (keep the earlier/first match)
  const filtered: typeof allMatches = [];
  for (const m of allMatches) {
    const overlaps = filtered.some(
      (existing) => m.start < existing.end && m.end > existing.start
    );
    if (!overlaps) {
      filtered.push(m);
    }
  }

  // Assign token numbers in document order (ascending)
  const tokenMap = new Map<typeof allMatches[number], string>();
  for (const m of filtered) {
    const prefix = m.pattern.prefix;
    counters[prefix] = (counters[prefix] || 0) + 1;
    tokenMap.set(m, `[${prefix}_${counters[prefix]}]`);
  }

  // Replace from end to start to preserve earlier positions
  for (let i = filtered.length - 1; i >= 0; i--) {
    const m = filtered[i];
    const token = tokenMap.get(m)!;

    redactions.push({
      token,
      original: m.original,
      type: m.pattern.name,
      position: m.start,
    });

    redactedText =
      redactedText.substring(0, m.start) +
      token +
      redactedText.substring(m.end);
  }

  // Reverse redactions so they're in document order (start to end)
  redactions.reverse();

  return {
    redactedText,
    redactions,
    piiDetected: redactions.length > 0,
    redactionCount: redactions.length,
  };
}

/**
 * Rehydrates text by replacing indexed tokens back with original PII values.
 *
 * Example:
 *   Input:  "I've drafted an email to [EMAIL_1] about Q4..."
 *   Map:    [{ token: "[EMAIL_1]", original: "john@acme.com", ... }]
 *   Output: "I've drafted an email to john@acme.com about Q4..."
 */
export function rehydratePII(
  text: string,
  redactions: RedactionEntry[]
): string {
  let result = text;
  for (const entry of redactions) {
    // Replace all occurrences of this token (LLM may repeat tokens)
    result = result.split(entry.token).join(entry.original);
  }
  return result;
}

/**
 * Creates a summary of redactions for logging (no raw PII values).
 */
export function getRedactionSummary(
  redactions: RedactionEntry[]
): Record<string, number> {
  const summary: Record<string, number> = {};
  for (const entry of redactions) {
    summary[entry.type] = (summary[entry.type] || 0) + 1;
  }
  return summary;
}
