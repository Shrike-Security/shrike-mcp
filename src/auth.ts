/**
 * API Key Authentication
 * Validates API keys against the backend and resolves to customer_id
 */

import { config } from './config.js';

export interface AuthResult {
  valid: boolean;
  customerId?: string;
  tier?: string;
  error?: string;
}

// Cache validated keys for 5 minutes to reduce backend calls
const keyCache = new Map<string, { result: AuthResult; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Validates an API key against the backend
 * Returns customer_id and tier for rate limiting
 */
export async function validateApiKey(apiKey: string): Promise<AuthResult> {
  if (!apiKey) {
    return { valid: false, error: 'API key is required' };
  }

  // Check cache first
  const cached = keyCache.get(apiKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.result;
  }

  try {
    const response = await fetch(`${config.backendUrl}/api/internal/validate-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ api_key: apiKey }),
    });

    if (!response.ok) {
      const result: AuthResult = {
        valid: false,
        error: `Backend returned ${response.status}`,
      };
      return result;
    }

    const data = await response.json() as {
      valid: boolean;
      customer_id?: string;
      tier?: string;
      error?: string;
    };

    const result: AuthResult = {
      valid: data.valid,
      customerId: data.customer_id,
      tier: data.tier,
      error: data.error,
    };

    // Cache successful validations
    if (result.valid) {
      keyCache.set(apiKey, {
        result,
        expiresAt: Date.now() + CACHE_TTL_MS,
      });
    }

    return result;
  } catch (error) {
    console.error('API key validation failed:', error);
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Validation failed',
    };
  }
}

/**
 * Extracts API key from Authorization header
 * Supports: "Bearer <key>" or raw key
 */
export function extractApiKey(authHeader: string | undefined): string | null {
  if (!authHeader) return null;

  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }

  // Allow raw key for simplicity
  return authHeader.trim();
}

/**
 * Clears the key cache (useful for testing)
 */
export function clearKeyCache(): void {
  keyCache.clear();
}
