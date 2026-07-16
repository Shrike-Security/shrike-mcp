/**
 * PII Pattern Sync — fetches canonical PII patterns from the backend at startup
 * and updates the client-side PII redactor so both sides stay in sync.
 *
 * On failure: logs a warning and keeps the hardcoded fallback patterns.
 */

import { config, getAuthHeaders } from '../config.js';
import { updatePIIPatterns, getPIIPatternCount, type PIIPattern } from './piiRedactor.js';

/**
 * Backend response from GET /api/pii/patterns.
 *
 * The backend now ships `prefix` as an authoritative field. Older backends
 * (pre-2026-07-01) omit it; the sync falls back to a threat_type-derived
 * prefix so no pattern is ever silently dropped. That's the whole point of
 * moving prefix resolution to the backend — Presidio-style, recognizer
 * owns its entity tag, client stays dumb.
 */
interface BackendPIIResponse {
  patterns: Array<{
    pattern: string;
    threat_type: string;
    confidence: number;
    description: string;
    prefix?: string; // authoritative when present; derived locally when absent
  }>;
  total: number;
  version: string;
}

/**
 * Fallback prefix derivation for backends that don't yet ship the
 * `prefix` field. Matches the backend's derivePIIPrefix() in
 * pii_handler.go — strip `pii_` and uppercase. Never returns empty:
 * unknown threat_types become their own uppercase tag (e.g.
 * `pii_wallet_eth` → `WALLET_ETH`) instead of being dropped.
 *
 * The point is: no threat_type ever silently disappears, and adding a
 * new backend pattern requires zero client changes.
 */
function fallbackPrefixFor(threatType: string): string {
  const stripped = threatType.startsWith('pii_') ? threatType.slice(4) : threatType;
  return stripped.toUpperCase() || 'PII';
}

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

    let derivedFallbackCount = 0;

    for (const p of data.patterns) {
      // Backend is the source of truth for the redaction tag. If it
      // ships a prefix (post-2026-07-01), use it verbatim. If not,
      // derive locally so no pattern is ever silently dropped — this
      // is the whole reason PREFIX_MAP was retired.
      let prefix = p.prefix;
      if (!prefix) {
        prefix = fallbackPrefixFor(p.threat_type);
        derivedFallbackCount++;
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

    if (derivedFallbackCount > 0) {
      // Not an error — expected for older backends. Log so operators can
      // see if a backend upgrade would give them explicit prefixes.
      console.error(`[PII] ${derivedFallbackCount}/${data.patterns.length} patterns used locally-derived prefix (backend older than 2026-07-01)`);
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
