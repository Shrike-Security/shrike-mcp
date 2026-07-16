/**
 * Unit tests for piiSync — verifies the backend-owned prefix contract.
 *
 * The 2026-07-01 launch retest surfaced an IP-redaction failure caused
 * by a client-side allowlist (PREFIX_MAP) that silently dropped any
 * threat_type it hadn't heard of. The architectural fix moves prefix
 * resolution to the backend (Presidio-style — the recognizer owns its
 * entity tag) and has the client fall back to a threat_type-derived
 * prefix if a backend ships without it. Net: no threat_type ever
 * silently disappears, and adding a new backend pattern requires zero
 * client changes.
 *
 * These tests lock in that behavior.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { syncPIIPatterns } from './piiSync.js';
import { redactPII } from './piiRedactor.js';

const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    scanTimeoutMs: 5000,
    debug: false,
  },
  getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test' }),
}));

vi.spyOn(console, 'error').mockImplementation(() => {});

describe('syncPIIPatterns — backend-owned prefix contract', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses the backend-shipped prefix verbatim when present (modern backend)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        patterns: [
          { pattern: '[a-z]+@[a-z]+\\.[a-z]+', threat_type: 'pii_email', prefix: 'EMAIL', confidence: 0.95, description: 'Email' },
          { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', threat_type: 'pii_ip_address', prefix: 'IP', confidence: 0.75, description: 'IPv4' },
        ],
        total: 2,
        version: '2026-07-01',
      }),
    });

    await syncPIIPatterns();

    const result = redactPII('email x@y.co and ip 192.168.1.100');
    expect(result.redactedText).not.toContain('192.168.1.100');
    expect(result.redactedText).toMatch(/\[IP_\d+\]/);
  });

  it('falls back to threat_type-derived prefix when backend omits it (old backend)', async () => {
    // Simulate a pre-2026-07-01 backend that doesn't ship the prefix field.
    // The client must NOT drop the pattern — instead it derives PII_IP_ADDRESS
    // → IP_ADDRESS from the threat_type. Different tag than a modern backend's
    // "IP", but redaction still fires. That's the whole point: no silent drop.
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        patterns: [
          { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', threat_type: 'pii_ip_address', confidence: 0.75, description: 'IPv4' },
        ],
        total: 1,
        version: '2026-06-01',
      }),
    });

    await syncPIIPatterns();

    const result = redactPII('server at 192.168.1.100');
    expect(result.redactedText).not.toContain('192.168.1.100');
    // Derived prefix is IP_ADDRESS (uppercased threat_type minus pii_).
    // Modern backends ship 'IP' explicitly.
    expect(result.redactedText).toMatch(/\[IP_ADDRESS_\d+\]/);
  });

  it('never silently drops unknown threat_types (regressed 2026-07-01)', async () => {
    // A backend adds a hypothetical new pattern we've never seen. The client
    // must sync it, not skip it. Prior behavior: silently dropped.
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        patterns: [
          { pattern: '0x[a-fA-F0-9]{40}', threat_type: 'pii_wallet_eth', confidence: 0.9, description: 'ETH wallet' },
        ],
        total: 1,
        version: '2026-08-01',
      }),
    });

    await syncPIIPatterns();

    const result = redactPII('send funds to 0x742d35Cc6634C0532925a3b844Bc9e7595f89999');
    expect(result.redactedText).not.toContain('0x742d35Cc6634C0532925a3b844Bc9e7595f89999');
    expect(result.redactedText).toMatch(/\[WALLET_ETH_\d+\]/);
  });

  it('logs when patterns used locally-derived prefix so operators can spot old backends', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        patterns: [
          { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', threat_type: 'pii_ip_address', confidence: 0.75, description: 'IPv4' }, // no prefix
          { pattern: '[a-z]+@[a-z]+\\.[a-z]+', threat_type: 'pii_email', prefix: 'EMAIL', confidence: 0.95, description: 'Email' }, // has prefix
        ],
        total: 2,
        version: '2026-06-15',
      }),
    });

    const errorSpy = vi.spyOn(console, 'error');
    await syncPIIPatterns();

    const derivedNote = errorSpy.mock.calls.find(c => String(c[0]).includes('locally-derived prefix'));
    expect(derivedNote).toBeTruthy();
  });
});
