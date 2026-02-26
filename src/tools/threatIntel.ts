/**
 * get_threat_intel Tool
 * Retrieves threat intelligence: detection coverage, active pattern stats,
 * learning system status, and optionally full pattern details.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { config, getAuthHeaders } from '../config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf-8'));
const VERSION: string = pkg.version;

export interface ThreatIntelInput {
  category?: string;
  include?: 'summary' | 'full';
}

export interface ThreatPattern {
  id: string;
  pattern: string;
  threatType: string;
  confidence: number;
  hitCount: number;
  description: string;
}

export interface ThreatIntelStats {
  activePatterns: number;
  candidatePatterns: number;
  totalDetections: number;
  llmCallsAvoided: number;
  estimatedCostSaved: string;
  avgConfidence: number;
  semanticEnabled: boolean;
}

export interface CategoryCoverage {
  category: string;
  patternCount: number;
  description: string;
}

export interface ThreatIntelResult {
  success: boolean;
  serverVersion: string;
  patterns: ThreatPattern[];
  categories: string[];
  totalPatterns: number;
  lastUpdated?: string;
  stats?: ThreatIntelStats;
  coverage?: CategoryCoverage[];
  error?: string;
}

/**
 * Retrieves threat intelligence from ThreatSense
 */
export async function getThreatIntel(input: ThreatIntelInput): Promise<ThreatIntelResult> {
  try {
    const params = new URLSearchParams();
    if (input.category) params.set('category', input.category);
    const include = input.include || 'summary';
    params.set('include', include);

    const response = await fetch(
      `${config.backendUrl}/api/threatsense/patterns?${params.toString()}`,
      {
        method: 'GET',
        headers: getAuthHeaders(),
      }
    );

    if (!response.ok) {
      return {
        success: false,
        serverVersion: VERSION,
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
      stats?: {
        active_patterns: number;
        candidate_patterns: number;
        total_detections: number;
        llm_calls_avoided: number;
        estimated_cost_saved: string;
        avg_confidence: number;
        semantic_enabled: boolean;
      };
      coverage?: Array<{
        category: string;
        pattern_count: number;
        description: string;
      }>;
    };

    return {
      success: true,
      serverVersion: VERSION,
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
      stats: data.stats ? {
        activePatterns: data.stats.active_patterns,
        candidatePatterns: data.stats.candidate_patterns,
        totalDetections: data.stats.total_detections,
        llmCallsAvoided: data.stats.llm_calls_avoided,
        estimatedCostSaved: data.stats.estimated_cost_saved,
        avgConfidence: data.stats.avg_confidence,
        semanticEnabled: data.stats.semantic_enabled,
      } : undefined,
      coverage: data.coverage?.map((c) => ({
        category: c.category,
        patternCount: c.pattern_count,
        description: c.description,
      })),
    };
  } catch (error) {
    console.error(`Get threat intel failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    return {
      success: false,
      serverVersion: VERSION,
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
  description: 'Retrieves threat intelligence: detection coverage across 10 attack categories, active pattern stats, learning system status, and cost savings. Use include="full" for individual pattern details.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      category: {
        type: 'string',
        description: 'Filter by threat category (e.g., injection, roleplay, pii_extraction, multilingual, command_injection)',
      },
      include: {
        type: 'string',
        enum: ['summary', 'full'],
        description: 'Level of detail: "summary" (default) returns stats + category coverage, "full" includes all individual patterns',
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
