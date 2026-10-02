/**
 * report_outcome Tool
 *
 * Closes the loop a scan opens. A scan proves an action was authorized; it
 * never proves the action ran. This reports what became of it, naming the
 * scan by the `scan_id` the verdict carried in its audit block.
 *
 * Best effort by design: a failed report must never change what the agent
 * does next, so every failure path returns a result rather than throwing.
 * Callable under quarantine, because reporting an outcome is not an action.
 *
 * Never send error text. The backend records a status and a time; a host's
 * error string carries prompt content and has no place on this path.
 */

import { config, getAuthHeaders } from '../config.js';

export type ActionOutcome = 'executed' | 'failed' | 'skipped';

export interface ReportOutcomeInput {
  scan_id: string;
  outcome: ActionOutcome;
  exit_status?: number;
}

export interface ReportOutcomeResult {
  recorded: boolean;
  scan_id: string;
  outcome: ActionOutcome;
  /** Backend status: recorded, already_recorded, not_found, already_closed. */
  status?: string;
  /** True when the scan held the action and this report closed its decision. */
  held?: boolean;
  error?: string;
}

const VALID_OUTCOMES: readonly string[] = ['executed', 'failed', 'skipped'];

export async function reportOutcome(input: ReportOutcomeInput): Promise<ReportOutcomeResult> {
  const scanId = (input.scan_id || '').trim();
  const outcome = input.outcome;

  if (!scanId) {
    return { recorded: false, scan_id: '', outcome, error: 'scan_id is required' };
  }
  if (!VALID_OUTCOMES.includes(outcome)) {
    return { recorded: false, scan_id: scanId, outcome, error: 'outcome must be executed, failed or skipped' };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.scanTimeoutMs);

  try {
    const body: Record<string, unknown> = {
      scan_id: scanId,
      outcome,
      ran_at: new Date().toISOString(),
      source: 'shrike-mcp',
    };
    if (Number.isInteger(input.exit_status)) {
      body.exit_status = input.exit_status;
    }

    const response = await fetch(`${config.backendUrl}/api/scan/outcome`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    const data = await response.json().catch(() => ({})) as { status?: string; held?: boolean };

    if (!response.ok) {
      // 404 means no scan of ours carries that id; 409 means it was already
      // answered and the first answer stands. Neither is worth a retry.
      return {
        recorded: false,
        scan_id: scanId,
        outcome,
        status: data.status,
        held: data.held,
        error: `Backend returned ${response.status}`,
      };
    }

    return { recorded: true, scan_id: scanId, outcome, status: data.status, held: data.held };
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      return { recorded: false, scan_id: scanId, outcome, error: 'Request timed out' };
    }
    return { recorded: false, scan_id: scanId, outcome, error: 'Request failed' };
  }
}

export const reportOutcomeTool = {
  name: 'report_outcome',
  description: `Report what became of an action Shrike scanned.

WHEN TO USE:
- After you run an action a Shrike scan allowed: report "executed", or "failed" with the exit status if you have one.
- After you decide not to run it: report "skipped".
- Report once per scan. The first answer is the record; a second is a conflict, not an update.

WHAT IT NEEDS: the scan_id from the audit block of the verdict that allowed the action.

WHAT IT RETURNS: whether the outcome was recorded, and whether the scan had held the action, in which case this report closes its decision.

WHAT IT DOES NOT DO: it is not a scan and not a verification. It records what you report. Never send error text — a status and a time are all this path carries.

ERROR HANDLING: Non-critical and best effort. A failed report never changes what you should do next; an unreported action simply reads as unconfirmed.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      scan_id: {
        type: 'string',
        description: 'The scan_id from the audit block of the verdict that governed this action.',
      },
      outcome: {
        type: 'string',
        enum: ['executed', 'failed', 'skipped'],
        description: 'executed = the action ran. failed = it ran and errored. skipped = it did not run.',
      },
      exit_status: {
        type: 'number',
        description: 'The host exit status, when there is one. Omit if unknown.',
      },
    },
    required: ['scan_id', 'outcome'],
  },
  annotations: {
    title: 'Report Outcome',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
};
