/**
 * report_bypass Tool
 * Reports a bypass to ThreatSense for pattern learning
 */

import { config, getAuthHeaders } from '../config.js';

export interface ReportBypassInput {
  prompt?: string;
  mutationType?: string;
  category?: string;
  notes?: string;
  // File-related bypass fields
  filePath?: string;
  fileContent?: string;
  // SQL-related bypass fields
  sqlQuery?: string;
  // Web search bypass fields
  searchQuery?: string;
}

export interface ReportBypassResult {
  success: boolean;
  patternId?: string;
  message: string;
}

/**
 * Builds the bypass prompt from various input types
 */
function buildBypassPrompt(input: ReportBypassInput): string {
  // If direct prompt is provided, use it
  if (input.prompt) {
    return input.prompt;
  }

  // File-related bypass: combine path and content
  if (input.filePath || input.fileContent) {
    const parts: string[] = [];
    if (input.filePath) {
      parts.push(`FILE_PATH: ${input.filePath}`);
    }
    if (input.fileContent) {
      parts.push(`FILE_CONTENT:\n${input.fileContent}`);
    }
    return parts.join('\n');
  }

  // SQL bypass
  if (input.sqlQuery) {
    return `SQL_QUERY: ${input.sqlQuery}`;
  }

  // Web search bypass
  if (input.searchQuery) {
    return `SEARCH_QUERY: ${input.searchQuery}`;
  }

  return '';
}

/**
 * Determines the default category based on input type
 */
function inferCategory(input: ReportBypassInput): string {
  if (input.category) {
    return input.category;
  }

  // File bypasses are likely secrets or PII
  if (input.filePath || input.fileContent) {
    return 'secrets_exposure';
  }

  // SQL bypasses
  if (input.sqlQuery) {
    return 'sql_injection';
  }

  // Web search bypasses are likely PII
  if (input.searchQuery) {
    return 'pii_in_search';
  }

  return 'prompt_injection';
}

/**
 * Reports a bypass to the ThreatSense learning system
 */
export async function reportBypass(input: ReportBypassInput): Promise<ReportBypassResult> {
  // Build the prompt from input fields
  const prompt = buildBypassPrompt(input);

  if (!prompt) {
    return {
      success: false,
      message: 'No bypass content provided. Use prompt, filePath/fileContent, sqlQuery, or searchQuery.',
    };
  }

  const category = inferCategory(input);

  try {
    const response = await fetch(`${config.backendUrl}/api/threatsense/report-bypass`, {
      method: 'POST',
      headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      body: JSON.stringify({
        prompt: prompt,
        mutation_type: input.mutationType || 'unknown',
        category: category,
        notes: input.notes,
        source: 'mcp-agent',
        confidence: 0.90, // Agent-reported bypasses at 0.90 confidence
      }),
    });

    if (!response.ok) {
      return {
        success: false,
        message: `Backend returned ${response.status}`,
      };
    }

    const data = await response.json() as {
      success: boolean;
      pattern_id?: string;
      message?: string;
    };

    return {
      success: data.success,
      patternId: data.pattern_id,
      message: data.message || 'Bypass reported successfully',
    };
  } catch (error) {
    console.error(`Report bypass failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Report failed',
    };
  }
}

/**
 * MCP Tool definition for report_bypass
 */
export const reportBypassTool = {
  name: 'report_bypass',
  description: `Reports content that bypassed security checks to help improve detection.

Supports multiple bypass types:
- Prompt bypasses: Use 'prompt' field
- File write bypasses: Use 'filePath' and/or 'fileContent' fields
- SQL bypasses: Use 'sqlQuery' field
- Web search bypasses: Use 'searchQuery' field

The bypass will be analyzed and may generate a new detection pattern.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      prompt: {
        type: 'string',
        description: 'The prompt that bypassed security detection',
      },
      filePath: {
        type: 'string',
        description: 'File path for file_write bypasses (e.g., config.yaml with undetected secrets)',
      },
      fileContent: {
        type: 'string',
        description: 'File content that should have been blocked (e.g., AWS keys, SSN)',
      },
      sqlQuery: {
        type: 'string',
        description: 'SQL query that bypassed injection detection',
      },
      searchQuery: {
        type: 'string',
        description: 'Web search query with undetected PII',
      },
      mutationType: {
        type: 'string',
        description: 'Type of mutation used (e.g., semantic_rewrite, encoding_exploit, unicode_tricks)',
        enum: [
          'semantic_rewrite',
          'character_injection',
          'encoding_exploit',
          'unicode_tricks',
          'context_manipulation',
          'instruction_override',
          'unknown',
        ],
      },
      category: {
        type: 'string',
        description: 'Threat category (auto-inferred if not provided)',
        enum: [
          'prompt_injection',
          'jailbreak',
          'pii_extraction',
          'secrets_exposure',
          'sql_injection',
          'path_traversal',
          'pii_in_search',
        ],
      },
      notes: {
        type: 'string',
        description: 'Additional notes about the bypass',
      },
    },
    required: [],
  },
  annotations: {
    title: 'Report Bypass',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
};
