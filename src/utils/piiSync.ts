/**
 * PII Pattern Sync — fetches canonical PII patterns from the backend at startup
 * and updates the client-side PII redactor so both sides stay in sync.
 *
 * On failure: logs a warning and keeps the hardcoded fallback patterns.
 */

import { config, getAuthHeaders } from '../config.js';
import { updatePIIPatterns, getPIIPatternCount, type PIIPattern } from './piiRedactor.js';

/**
 * Backend response from GET /api/pii/patterns
 */
interface BackendPIIResponse {
  patterns: Array<{
    pattern: string;
    threat_type: string;
    confidence: number;
    description: string;
  }>;
  total: number;
  version: string;
}

/**
 * Maps backend threat_type to MCP token prefix.
 * e.g. pii_ssn → SSN, so redacted tokens become [SSN_1], [SSN_2].
 */
const PREFIX_MAP: Record<string, string> = {
  pii_ssn: 'SSN',
  pii_ssn_alt: 'SSN',
  pii_credit_card: 'CARD',
  pii_email: 'EMAIL',
  pii_phone: 'PHONE',
  pii_phone_intl: 'PHONE',
  pii_street_address: 'ADDR',
  pii_city_state_zip: 'ADDR',
  pii_bank_account: 'ACCOUNT',
  pii_routing_number: 'ROUTING',
  pii_iban: 'IBAN',
  pii_swift: 'SWIFT',
  pii_medical_record: 'MRN',
  pii_health_insurance: 'HEALTHID',
  pii_drivers_license: 'DL',
  pii_passport: 'PASSPORT',
  pii_dob: 'DOB',
  pii_medical_diagnosis: 'MEDINFO',
  pii_medical_code: 'MEDCODE',
  pii_prescription: 'RX',
  pii_ein: 'TAXID',
  pii_tin: 'TAXID',
  pii_potential_name: 'NAME',
};

/**
 * Converts a backend threat_type to a short name for the redaction entry.
 * e.g. "pii_credit_card" → "credit_card"
 */
function threatTypeToName(threatType: string): string {
  return threatType.startsWith('pii_') ? threatType.slice(4) : threatType;
}

/**
 * Fetches PII patterns from the backend and updates the local PII redactor.
 * Safe to call at startup — on failure, keeps existing hardcoded patterns.
 */
export async function syncPIIPatterns(): Promise<void> {
  const fallbackCount = getPIIPatternCount();

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${config.backendUrl}/api/pii/patterns`, {
      method: 'GET',
      headers: getAuthHeaders(),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`[PII] Pattern sync failed: backend returned ${response.status}, keeping ${fallbackCount} fallback patterns`);
      return;
    }

    const data = await response.json() as BackendPIIResponse;

    if (!data.patterns || data.patterns.length === 0) {
      console.error(`[PII] Backend returned 0 patterns, keeping ${fallbackCount} fallback patterns`);
      return;
    }

    // Convert backend patterns to PIIPattern format
    const converted: PIIPattern[] = [];

    for (const p of data.patterns) {
      const prefix = PREFIX_MAP[p.threat_type];
      if (!prefix) {
        // Unknown threat type — skip silently (backend may have new types)
        continue;
      }

      try {
        // Go regex → JS RegExp (global + case-insensitive)
        // Strip Go-specific (?i) inline flag — JS uses 'gi' constructor arg instead
        let regexStr = p.pattern;
        if (regexStr.startsWith('(?i)')) {
          regexStr = regexStr.slice(4);
        }
        const regex = new RegExp(regexStr, 'gi');
        converted.push({
          name: threatTypeToName(p.threat_type),
          regex,
          prefix,
        });
      } catch {
        // Invalid regex (Go-specific syntax not supported in JS) — skip
        console.error(`[PII] Skipping invalid pattern for ${p.threat_type}: regex compilation failed`);
      }
    }

    if (converted.length === 0) {
      console.error(`[PII] All ${data.patterns.length} backend patterns failed conversion, keeping ${fallbackCount} fallback patterns`);
      return;
    }

    // Sort: higher confidence patterns first (more specific = less FP)
    converted.sort((a, b) => {
      const aConf = data.patterns.find(p => threatTypeToName(p.threat_type) === a.name)?.confidence ?? 0;
      const bConf = data.patterns.find(p => threatTypeToName(p.threat_type) === b.name)?.confidence ?? 0;
      return bConf - aConf;
    });

    updatePIIPatterns(converted);
    console.error(`[PII] Synced ${converted.length} patterns from backend (was ${fallbackCount} hardcoded), version=${data.version}`);

  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      console.error(`[PII] Pattern sync timed out, keeping ${fallbackCount} fallback patterns`);
    } else {
      console.error(`[PII] Pattern sync failed: ${error instanceof Error ? error.message : 'Unknown error'}, keeping ${fallbackCount} fallback patterns`);
    }
  }
}
