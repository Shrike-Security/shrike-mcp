/**
 * OAuth 2.0 In-Memory Stores
 *
 * Provides client registration storage and authorization code management
 * for the MCP OAuth flow. For single-instance deployments; back with a
 * database for horizontal scaling.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

// ─── Authorization Code Store ───────────────────────────────────────────────

export interface AuthorizationCodeEntry {
  clientId: string;
  customerId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  expiresAt: number;
}

const AUTH_CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export class AuthorizationCodeStore {
  private codes = new Map<string, AuthorizationCodeEntry>();
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
    // Don't block process exit
    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
  }

  /**
   * Generates and stores an authorization code for the given session.
   */
  create(entry: Omit<AuthorizationCodeEntry, 'expiresAt'>): string {
    const code = randomBytes(32).toString('hex');
    this.codes.set(code, {
      ...entry,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });
    return code;
  }

  /**
   * Retrieves and consumes an authorization code (single-use).
   */
  consume(code: string): AuthorizationCodeEntry | undefined {
    const entry = this.codes.get(code);
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) {
      this.codes.delete(code);
      return undefined;
    }
    this.codes.delete(code);
    return entry;
  }

  /**
   * Retrieves an authorization code entry without consuming it.
   * Used by challengeForAuthorizationCode.
   */
  peek(code: string): AuthorizationCodeEntry | undefined {
    const entry = this.codes.get(code);
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) {
      this.codes.delete(code);
      return undefined;
    }
    return entry;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [code, entry] of this.codes) {
      if (entry.expiresAt < now) {
        this.codes.delete(code);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
    this.codes.clear();
  }
}

// ─── OAuth Client Store ─────────────────────────────────────────────────────

/**
 * In-memory implementation of OAuthRegisteredClientsStore.
 * Supports dynamic client registration (RFC 7591) as required by the MCP SDK.
 * Claude's MCP client will auto-register on first connection.
 */
export class ClientStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.clients.get(clientId);
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
  ): Promise<OAuthClientInformationFull> {
    const clientId = randomUUID();
    const clientSecret = randomBytes(32).toString('hex');

    const registered: OAuthClientInformationFull = {
      ...client,
      client_id: clientId,
      client_secret: clientSecret,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      // Secret does not expire
      client_secret_expires_at: 0,
    };

    this.clients.set(clientId, registered);
    return registered;
  }
}
