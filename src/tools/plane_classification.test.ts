/**
 * Contract test: MCP tool plane classification.
 *
 * Every scan tool declares its governance plane through the MCP `_meta`
 * extension slot on the tool object:
 *
 *   _meta: {
 *     'shrike/scan_class': 'observe' | 'act',
 *     'shrike/quarantine_gated': boolean,
 *     'shrike/contract_version': string,
 *   }
 *
 * IMPORTANT — _meta, not annotations. MCP's ToolAnnotationsSchema is a
 * closed Zod object using $strip mode, which silently drops any field
 * not in the schema (title, readOnlyHint, destructiveHint, idempotentHint,
 * openWorldHint). Placing scanClass/quarantineGated on annotations means
 * they are dropped at tools/list serialization and never reach the wire —
 * this was caught by external testing on 2026-07-03 after the first
 * classification attempt, and the fields were moved to _meta which is
 * z.ZodRecord and preserves arbitrary keys.
 *
 * This file has two independent tests:
 *
 *   1. Static tool object test — reads _meta from each tool export and
 *      pins the intended classification. Catches "did the author set
 *      the field."
 *
 *   2. SDK wire test — parses each tool through the SDK's ToolSchema.
 *      Catches "does the SDK preserve it end-to-end to tools/list."
 *      This class of check would have caught the annotations-strip bug
 *      before ship.
 *
 * Product principle: content scanning stays available under
 * session_locked; action scanning refuses to authorize side effects.
 * Behavior is asymmetric by design; contract is symmetric — one field
 * shape, enforced identically across the whole tool set, verified from
 * outside the code by the wire test. See the symmetric-contract principle.
 */

import { describe, it, expect } from 'vitest';
import { ToolSchema } from '@modelcontextprotocol/sdk/types.js';
import { scanPromptTool } from './scan.js';
import { scanResponseTool } from './scanResponse.js';
import { scanCommandTool } from './command.js';
import { scanSQLQueryTool } from './sqlQuery.js';
import { scanWebSearchTool } from './webSearch.js';
import { scanFileWriteTool } from './fileWrite.js';
import { scanA2AMessageTool } from './a2aMessage.js';
import { scanAgentCardTool } from './agentCard.js';

type PlaneMeta = {
  scanClass: 'observe' | 'act' | undefined;
  quarantineGated: boolean | undefined;
  contractVersion: string | undefined;
};

function readPlaneFromMeta(meta: Record<string, unknown> | undefined): PlaneMeta {
  const m = meta ?? {};
  return {
    scanClass: m['shrike/scan_class'] as 'observe' | 'act' | undefined,
    quarantineGated: m['shrike/quarantine_gated'] as boolean | undefined,
    contractVersion: m['shrike/contract_version'] as string | undefined,
  };
}

const OBSERVE_TOOLS = [
  { name: 'scan_prompt', tool: scanPromptTool },
  { name: 'scan_response', tool: scanResponseTool },
];

const ACT_TOOLS = [
  { name: 'scan_command', tool: scanCommandTool },
  { name: 'scan_sql_query', tool: scanSQLQueryTool },
  { name: 'scan_web_search', tool: scanWebSearchTool },
  { name: 'scan_file_write', tool: scanFileWriteTool },
  { name: 'scan_a2a_message', tool: scanA2AMessageTool },
  { name: 'scan_agent_card', tool: scanAgentCardTool },
];

// -----------------------------------------------------------------------
// Static test: read plane fields from each tool's _meta directly.
// -----------------------------------------------------------------------

describe('MCP tool plane classification — static _meta on tool object', () => {
  it.each(OBSERVE_TOOLS)(
    '$name has _meta shrike/scan_class=observe + shrike/quarantine_gated=false',
    ({ tool }) => {
      const p = readPlaneFromMeta((tool as { _meta?: Record<string, unknown> })._meta);
      expect(p.scanClass).toBe('observe');
      expect(p.quarantineGated).toBe(false);
      expect(p.contractVersion).toBeTruthy();
    },
  );

  it.each(ACT_TOOLS)(
    '$name has _meta shrike/scan_class=act + shrike/quarantine_gated=true',
    ({ tool }) => {
      const p = readPlaneFromMeta((tool as { _meta?: Record<string, unknown> })._meta);
      expect(p.scanClass).toBe('act');
      expect(p.quarantineGated).toBe(true);
      expect(p.contractVersion).toBeTruthy();
    },
  );

  it('total tool count is 8 (2 observe + 6 act) — update this test when adding a tool', () => {
    expect(OBSERVE_TOOLS.length + ACT_TOOLS.length).toBe(8);
    expect(OBSERVE_TOOLS.length).toBe(2);
    expect(ACT_TOOLS.length).toBe(6);
  });
});

// -----------------------------------------------------------------------
// Wire test: parse each tool through the MCP SDK's ToolSchema.
//
// This is the check that catches the "SDK strips unknown fields" bug
// class. If a future refactor moves the plane fields back to annotations
// (a $strip Zod object) or into any other closed schema, this test fails
// even if the static test still passes on the raw tool object.
// -----------------------------------------------------------------------

describe('MCP tool plane classification — survives SDK ToolSchema serialization', () => {
  const ALL_TOOLS = [...OBSERVE_TOOLS, ...ACT_TOOLS];

  it.each(ALL_TOOLS)(
    '$name plane fields survive ToolSchema.parse (not stripped by the SDK)',
    ({ tool }) => {
      const parsed = ToolSchema.parse({ name: (tool as { name: string }).name, ...tool });
      const p = readPlaneFromMeta(parsed._meta);
      expect(p.scanClass, 'shrike/scan_class survived SDK parse').toBeDefined();
      expect(p.quarantineGated, 'shrike/quarantine_gated survived SDK parse').toBeDefined();
      expect(p.contractVersion, 'shrike/contract_version survived SDK parse').toBeDefined();
    },
  );

  it('standard hint annotations (readOnlyHint, etc.) still survive alongside _meta', () => {
    const parsed = ToolSchema.parse({ name: 'scan_command', ...scanCommandTool });
    expect(parsed.annotations?.readOnlyHint).toBe(true);
    expect(parsed.annotations?.destructiveHint).toBe(false);
    expect(parsed.annotations?.idempotentHint).toBe(true);
    expect(parsed.annotations?.openWorldHint).toBe(true);
    // If a future refactor accidentally reintroduces shrike/* on annotations,
    // the annotations object should NOT expose them (SDK strips) — this line
    // documents the SDK's stripping behavior so the reason for _meta stays
    // discoverable in the test file.
    expect((parsed.annotations as unknown as Record<string, unknown>)['shrike/scan_class']).toBeUndefined();
  });
});
