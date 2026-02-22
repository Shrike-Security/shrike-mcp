/**
 * KeyRotationManager — polls a KeyProvider at a configurable interval
 * and fires a callback when the key changes. Supports graceful error
 * handling (failed polls retain the old key).
 */

import type { KeyProvider } from './keyProvider.js';

export interface KeyRotationOptions {
  /** Poll interval in milliseconds. Default 300000 (5 min). Set 0 to disable polling. */
  pollIntervalMs?: number;
  /** Called when the key changes (new key passed as argument) */
  onKeyChanged?: (newKey: string) => void;
}

export class KeyRotationManager {
  private provider: KeyProvider;
  private currentKey: string | null = null;
  private pollIntervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  private onKeyChanged?: (newKey: string) => void;

  constructor(provider: KeyProvider, options?: KeyRotationOptions) {
    this.provider = provider;
    this.pollIntervalMs = options?.pollIntervalMs ?? 5 * 60 * 1000;
    this.onKeyChanged = options?.onKeyChanged;
  }

  /** Fetch the key for the first time and start polling. */
  async initialize(): Promise<string | null> {
    this.currentKey = await this.provider.getKey();
    this.startPolling();
    return this.currentKey;
  }

  /** Return the current cached key. */
  getKey(): string | null {
    return this.currentKey;
  }

  /** Force an immediate refresh from the provider. Returns the (possibly new) key. */
  async refresh(): Promise<string | null> {
    try {
      const newKey = await this.provider.getKey();
      if (newKey && newKey !== this.currentKey) {
        console.error(`[KeyRotation] Key refreshed via ${this.provider.name()} provider`);
        this.currentKey = newKey;
        this.onKeyChanged?.(newKey);
      }
      return this.currentKey;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[KeyRotation] Refresh failed: ${message}`);
      return this.currentKey;
    }
  }

  /** Stop polling and clean up. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.provider.close?.();
  }

  /** Return the underlying provider (for 401 retry to force refresh). */
  getProvider(): KeyProvider {
    return this.provider;
  }

  // -----------------------------------------------------------------------
  // Private
  // -----------------------------------------------------------------------

  private startPolling(): void {
    if (this.pollIntervalMs <= 0) return;

    this.timer = setInterval(async () => {
      try {
        const newKey = await this.provider.getKey();
        if (newKey && newKey !== this.currentKey) {
          console.error(
            `[KeyRotation] Key rotated via ${this.provider.name()} provider`,
          );
          this.currentKey = newKey;
          this.onKeyChanged?.(newKey);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`[KeyRotation] Poll failed: ${message}`);
        // Keep using the existing key on failure
      }
    }, this.pollIntervalMs);
  }
}
