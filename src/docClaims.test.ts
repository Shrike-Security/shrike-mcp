/**
 * Doc-claim guard: the MCP README + help text must not contradict the running
 * code. Every failure here is a claim a prospect's AI would catch when vetting
 * the package. Grounds each claim in a source constant where one exists
 * (VALID_TOOL_NAMES), and in the published canonical values otherwise
 * (15 tools · 9 layers · fail-closed · free tier = L1-L5,
 * LLM semantic is Pro+ · Go SDK not published).
 *
 * This is the systemic net from the 2026-07 doc-vs-code grounding audit: it
 * turns the manual claim-consistency sweep into a CI gate.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { VALID_TOOL_NAMES } from './config.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const README = readFileSync(join(HERE, '..', 'README.md'), 'utf8');
const INDEX = readFileSync(join(HERE, 'index.ts'), 'utf8');
const TOOL_COUNT = VALID_TOOL_NAMES.length;

describe('MCP doc claims vs running code', () => {
  it('canonical tool count is 15', () => {
    expect(TOOL_COUNT).toBe(15);
  });

  // A name in VALID_TOOL_NAMES that nothing registers does not error: the
  // list builder does TOOL_REGISTRY[name]?.definition and filters falsy, so
  // the tool silently never appears. Same for the bundled map. Enumerate both
  // against the canonical list rather than trusting three hand-kept copies.
  it('every valid tool name is registered and bundled', () => {
    const registry = INDEX.split('const TOOL_REGISTRY')[1].split('\n};')[0];
    const registered = [...registry.matchAll(/^  ([a-z0-9_]+): \{$/gm)].map(m => m[1]);
    const bundled = INDEX.split('const BUNDLED_TYPE_MAP')[1].split('\n};')[0];
    const bundledTargets = [...bundled.matchAll(/'([a-z0-9_]+)',/g)].map(m => m[1]);

    for (const name of VALID_TOOL_NAMES) {
      expect(registered, `${name} missing from TOOL_REGISTRY`).toContain(name);
      expect(bundledTargets, `${name} missing from BUNDLED_TYPE_MAP`).toContain(name);
    }
    expect(registered.length).toBe(TOOL_COUNT);
  });

  it('README states the real tool count and carries no stale count', () => {
    expect(README).toMatch(new RegExp(`\\b${TOOL_COUNT}\\b[^\\n]*tools`));
    expect(README).not.toMatch(/\b(10|11|12|13|14)\s+(security\s+)?tools\b/);
  });

  it('every tool-count mention in index.ts equals the real count', () => {
    const mentions = [
      ...INDEX.matchAll(/all (\d+) tools/gi),
      ...INDEX.matchAll(/default: all (\d+)/gi),
    ];
    expect(mentions.length).toBeGreaterThan(0);
    for (const m of mentions) {
      expect(Number(m[1])).toBe(TOOL_COUNT);
    }
  });

  it('does not advertise an unpublished Go SDK', () => {
    expect(README).not.toMatch(/go get/i);
    expect(README).not.toMatch(/\bGo SDK\b/);
  });

  it('free / Community tier does not claim LLM semantic (code: free = L1-L5, LLM is Pro+)', () => {
    expect(README).not.toMatch(/free to unlock LLM/i);
    expect(README).not.toMatch(/Community[^\n]*LLM[- ]powered semantic/i);
    // Community detection depth must read L1-L5, never L1-L7 (that grants LLM).
    expect(README).not.toMatch(/L1-L7/);
    // The L7 layer row must gate at Pro+, not Community+.
    expect(README).not.toMatch(/LLM semantic[^\n]*Community\+/i);
  });

  it('states a fail-closed default, never fail-open', () => {
    expect(README).toMatch(/fail-closed/i);
    expect(README).not.toMatch(/fail-open \(default\)/i);
  });

  it('does not link the dead Smithery server page', () => {
    expect(README).not.toMatch(/smithery\.ai\/server\/shrike-mcp/);
  });
});
