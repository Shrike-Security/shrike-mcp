/**
 * Token Bucket Rate Limiter
 * Per-customer rate limiting for MCP requests
 */

import { config } from '../config.js';

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

// Per-customer token buckets
const buckets = new Map<string, TokenBucket>();

// Cleanup interval: remove stale buckets every 10 minutes
const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const BUCKET_STALE_THRESHOLD_MS = 60 * 60 * 1000; // 1 hour

/**
 * Token bucket rate limiter
 * - Capacity: config.rateLimitPerMinute tokens
 * - Refill rate: capacity / 60 tokens per second
 */
export class RateLimiter {
  private readonly capacity: number;
  private readonly refillRate: number; // tokens per millisecond

  constructor() {
    this.capacity = config.rateLimitPerMinute;
    this.refillRate = this.capacity / 60000; // per millisecond

    // Start cleanup scheduler
    setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /**
   * Attempts to consume a token for the given customer
   * Returns true if allowed, false if rate limited
   */
  consume(customerId: string): { allowed: boolean; remaining: number; retryAfterMs?: number } {
    const now = Date.now();
    let bucket = buckets.get(customerId);

    if (!bucket) {
      bucket = {
        tokens: this.capacity,
        lastRefill: now,
      };
      buckets.set(customerId, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsed = now - bucket.lastRefill;
    const tokensToAdd = elapsed * this.refillRate;
    bucket.tokens = Math.min(this.capacity, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
      };
    }

    // Calculate retry time
    const tokensNeeded = 1 - bucket.tokens;
    const retryAfterMs = Math.ceil(tokensNeeded / this.refillRate);

    return {
      allowed: false,
      remaining: 0,
      retryAfterMs,
    };
  }

  /**
   * Gets the current token count for a customer
   */
  getRemaining(customerId: string): number {
    const bucket = buckets.get(customerId);
    if (!bucket) return this.capacity;

    // Calculate current tokens with refill
    const elapsed = Date.now() - bucket.lastRefill;
    const tokensToAdd = elapsed * this.refillRate;
    return Math.min(this.capacity, Math.floor(bucket.tokens + tokensToAdd));
  }

  /**
   * Removes stale buckets to prevent memory leaks
   */
  private cleanup(): void {
    const now = Date.now();
    let removed = 0;

    for (const [customerId, bucket] of buckets.entries()) {
      if (now - bucket.lastRefill > BUCKET_STALE_THRESHOLD_MS) {
        buckets.delete(customerId);
        removed++;
      }
    }

    if (removed > 0 && config.debug) {
      console.error(`RateLimiter: Cleaned up ${removed} stale buckets`);
    }
  }

  /**
   * Gets statistics about the rate limiter
   */
  getStats(): { activeBuckets: number; capacity: number } {
    return {
      activeBuckets: buckets.size,
      capacity: this.capacity,
    };
  }
}

// Singleton instance
export const rateLimiter = new RateLimiter();
