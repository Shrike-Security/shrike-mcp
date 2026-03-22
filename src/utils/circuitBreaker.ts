/**
 * Three-state circuit breaker for Shrike backend HTTP calls.
 *
 * States:
 *   CLOSED  → Normal operation. Failures are counted.
 *   OPEN    → Failing. Requests rejected with CircuitOpenError.
 *   HALF_OPEN → Recovery testing. Limited requests allowed.
 *
 * Transitions:
 *   CLOSED → OPEN: after failureThreshold consecutive failures
 *   OPEN → HALF_OPEN: after timeout elapses
 *   HALF_OPEN → CLOSED: after successThreshold successes
 *   HALF_OPEN → OPEN: on any failure
 */

export enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open',
}

export class CircuitOpenError extends Error {
  constructor(message = 'Circuit breaker is open') {
    super(message);
    this.name = 'CircuitOpenError';
  }
}

export interface CircuitBreakerConfig {
  /** Number of consecutive failures before opening. Default: 5 */
  failureThreshold?: number;
  /** Number of successes in half-open before closing. Default: 2 */
  successThreshold?: number;
  /** Duration in ms the circuit stays open before half-open. Default: 30000 */
  timeoutMs?: number;
  /** Max concurrent requests in half-open state. Default: 3 */
  maxHalfOpenRequests?: number;
  /** Called on state transitions */
  onStateChange?: (from: CircuitState, to: CircuitState) => void;
}

export interface CircuitBreakerStats {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailure: Date | null;
}

export class CircuitBreaker {
  private _state: CircuitState = CircuitState.CLOSED;
  private _failureCount = 0;
  private _successCount = 0;
  private _halfOpenCount = 0;
  private _openedAt = 0;
  private _lastFailure: Date | null = null;

  private readonly failureThreshold: number;
  private readonly successThreshold: number;
  private readonly timeoutMs: number;
  private readonly maxHalfOpenRequests: number;
  private readonly onStateChange?: (from: CircuitState, to: CircuitState) => void;

  constructor(config: CircuitBreakerConfig = {}) {
    this.failureThreshold = config.failureThreshold ?? 5;
    this.successThreshold = config.successThreshold ?? 2;
    this.timeoutMs = config.timeoutMs ?? 30_000;
    this.maxHalfOpenRequests = config.maxHalfOpenRequests ?? 3;
    this.onStateChange = config.onStateChange;
  }

  get state(): CircuitState {
    if (this._state === CircuitState.OPEN && Date.now() - this._openedAt >= this.timeoutMs) {
      return CircuitState.HALF_OPEN;
    }
    return this._state;
  }

  get stats(): CircuitBreakerStats {
    return {
      state: this._state,
      failureCount: this._failureCount,
      successCount: this._successCount,
      lastFailure: this._lastFailure,
    };
  }

  /**
   * Execute an async function through the circuit breaker.
   * @throws CircuitOpenError if the circuit is open
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.beforeRequest();
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private beforeRequest(): void {
    switch (this._state) {
      case CircuitState.CLOSED:
        return;

      case CircuitState.OPEN:
        if (Date.now() - this._openedAt >= this.timeoutMs) {
          this.setState(CircuitState.HALF_OPEN);
          this._halfOpenCount = 1;
          return;
        }
        throw new CircuitOpenError();

      case CircuitState.HALF_OPEN:
        this._halfOpenCount++;
        if (this._halfOpenCount > this.maxHalfOpenRequests) {
          this._halfOpenCount--;
          throw new CircuitOpenError('Too many requests in half-open state');
        }
        return;
    }
  }

  private onSuccess(): void {
    switch (this._state) {
      case CircuitState.CLOSED:
        this._failureCount = 0;
        this._successCount++;
        break;

      case CircuitState.HALF_OPEN:
        this._successCount++;
        if (this._successCount >= this.successThreshold) {
          this.setState(CircuitState.CLOSED);
          this._failureCount = 0;
          this._successCount = 0;
          this._halfOpenCount = 0;
        }
        break;
    }
  }

  private onFailure(): void {
    this._lastFailure = new Date();

    switch (this._state) {
      case CircuitState.CLOSED:
        this._failureCount++;
        if (this._failureCount >= this.failureThreshold) {
          this.setState(CircuitState.OPEN);
          this._openedAt = Date.now();
        }
        break;

      case CircuitState.HALF_OPEN:
        this.setState(CircuitState.OPEN);
        this._openedAt = Date.now();
        this._successCount = 0;
        this._halfOpenCount = 0;
        break;
    }
  }

  private setState(to: CircuitState): void {
    const from = this._state;
    if (from === to) return;
    this._state = to;
    console.error(`[shrike] Circuit breaker: ${from} → ${to}`);
    this.onStateChange?.(from, to);
  }
}

/**
 * Shared circuit breaker singleton for all Shrike scan tools.
 * All tools (scan_prompt, scan_response, scan_sql_query, scan_command, etc.)
 * share this instance so backend health is tracked holistically.
 */
export const scanCircuitBreaker = new CircuitBreaker({
  failureThreshold: 5,
  successThreshold: 2,
  timeoutMs: 30_000,
  onStateChange: (from, to) => {
    if (to === CircuitState.OPEN) {
      console.error('[shrike] WARNING: Scan circuit breaker OPEN — backend may be down');
    } else if (to === CircuitState.CLOSED) {
      console.error('[shrike] Scan circuit breaker recovered — backend is healthy');
    }
  },
});
