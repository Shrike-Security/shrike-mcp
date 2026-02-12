/**
 * get_threat_intel Tool
 * Retrieves current threat intelligence and detection patterns
 */

import { config, getAuthHeaders } from '../config.js';

export interface ThreatIntelInput {
  category?: string;
  limit?: number;
}

export interface ThreatPattern {
  id: string;
  pattern: string;
  threatType: string;
  confidence: number;
  hitCount: number;
  description: string;
}

export interface ThreatIntelResult {
  success: boolean;
  patterns: ThreatPattern[];
  categories: string[];
  totalPatterns: number;
  lastUpdated?: string;
  error?: string;
}

/**
 * Retrieves threat intelligence from ThreatSense
 */
export async function getThreatIntel(input: ThreatIntelInput): Promise<ThreatIntelResult> {
  try {
    const params = new URLSearchParams();
    if (input.category) params.set('category', input.category);
    if (input.limit) params.set('limit', String(input.limit));

    const response = await fetch(
      `${config.backendUrl}/api/threatsense/patterns?${params.toString()}`,
      {
        method: 'GET',
        headers: getAuthHeaders(),  // Includes Authorization header if API key is set
      }
    );

    if (!response.ok) {
      return {
        success: false,
        patterns: [],
        categories: [],
        totalPatterns: 0,
        error: `Backend returned ${response.status}`,
      };
    }

    const data = await response.json() as {
      patterns?: Array<{
        id: string;
        pattern: string;
        threat_type: string;
        confidence: number;
        hit_count: number;
        description?: string;
      }>;
      categories?: string[];
      total?: number;
      last_updated?: string;
    };

    return {
      success: true,
      patterns: (data.patterns || []).map((p) => ({
        id: p.id,
        pattern: p.pattern,
        threatType: p.threat_type,
        confidence: p.confidence,
        hitCount: p.hit_count,
        description: p.description || '',
      })),
      categories: data.categories || [],
      totalPatterns: data.total || 0,
      lastUpdated: data.last_updated,
    };
  } catch (error) {
    console.error('Get threat intel failed:', error);
    return {
      success: false,
      patterns: [],
      categories: [],
      totalPatterns: 0,
      error: error instanceof Error ? error.message : 'Request failed',
    };
  }
}

/**
 * MCP Tool definition for get_threat_intel
 */
export const getThreatIntelTool = {
  name: 'get_threat_intel',
  description: 'Retrieves current threat intelligence including active detection patterns, threat categories, and statistics.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      category: {
        type: 'string',
        description: 'Filter by threat category (e.g., prompt_injection, jailbreak, pii_extraction)',
      },
      limit: {
        type: 'number',
        description: 'Maximum number of patterns to return (default: 50)',
      },
    },
    required: [],
  },
  annotations: {
    title: 'Get Threat Intel',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};
