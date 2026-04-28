/**
 * OAuth 2.0 Server Provider for MCP
 *
 * Implements the OAuthServerProvider interface from the MCP SDK.
 * Acts as the OAuth authorization server for the Shrike MCP endpoint.
 *
 * Authorization flow:
 *   1. Claude (MCP client) dynamically registers → ClientStore
 *   2. Claude redirects user to our /authorize endpoint
 *   3. We redirect to the Shrike backend's OAuth login (Google/GitHub)
 *   4. Backend authenticates user, redirects back with a session token
 *   5. We issue an authorization code and redirect to Claude's redirect_uri
 *   6. Claude exchanges code for access + refresh tokens via /token
 *   7. Claude uses Bearer token on /mcp requests
 */

import { Response } from 'express';
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { config } from '../config.js';
import { validateApiKey } from '../auth.js';
import { ClientStore, AuthorizationCodeStore } from './store.js';

// ─── Configuration ──────────────────────────────────────────────────────────

const BACKEND_URL = config.backendUrl;
const ACCESS_TOKEN_TTL_S = 3600; // 1 hour
const REFRESH_TOKEN_TTL_S = 7 * 24 * 3600; // 7 days

// ─── Provider Implementation ────────────────────────────────────────────────

export class ShrikeOAuthProvider implements OAuthServerProvider {
  private _clientsStore = new ClientStore();
  private authCodes = new AuthorizationCodeStore();

  get clientsStore(): OAuthRegisteredClientsStore {
    return this._clientsStore;
  }

  /**
   * Begins the authorization flow.
   * Redirects the user to the Shrike backend's OAuth login page.
   * The backend handles Google/GitHub authentication, then redirects back
   * to our /oauth/callback with a session_token.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response,
  ): Promise<void> {
    // Encode MCP OAuth state into the backend's OAuth flow
    const mcpState = JSON.stringify({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes || [],
      state: params.state,
    });

    const encodedState = Buffer.from(mcpState).toString('base64url');

    // Redirect to the backend's MCP OAuth authorization endpoint.
    // This endpoint will show a consent screen or redirect to Google/GitHub.
    const authorizeUrl = new URL(`${BACKEND_URL}/api/v1/mcp-oauth/authorize`);
    authorizeUrl.searchParams.set('mcp_state', encodedState);
    authorizeUrl.searchParams.set('client_id', client.client_id);

    res.redirect(authorizeUrl.toString());
  }

  /**
   * Returns the PKCE code_challenge stored when the authorization code was created.
   */
  async challengeForAuthorizationCode(
    _client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<string> {
    const entry = this.authCodes.peek(authorizationCode);
    if (!entry) {
      throw new Error('Invalid or expired authorization code');
    }
    return entry.codeChallenge;
  }

  /**
   * Exchanges an authorization code for access + refresh tokens.
   * Calls the Shrike backend to generate JWT tokens for the authenticated user.
   */
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    _redirectUri?: string,
  ): Promise<OAuthTokens> {
    const entry = this.authCodes.consume(authorizationCode);
    if (!entry) {
      throw new Error('Invalid or expired authorization code');
    }

    if (entry.clientId !== client.client_id) {
      throw new Error('Client ID mismatch');
    }

    // Request tokens from the backend for this customer
    const response = await fetch(`${BACKEND_URL}/api/v1/mcp-oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        customer_id: entry.customerId,
        client_id: client.client_id,
        scopes: entry.scopes,
      }),
    });

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(`Token exchange failed: ${response.status} ${errBody}`);
    }

    const data = await response.json() as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    return {
      access_token: data.access_token,
      token_type: 'Bearer',
      expires_in: data.expires_in || ACCESS_TOKEN_TTL_S,
      refresh_token: data.refresh_token,
    };
  }

  /**
   * Exchanges a refresh token for a new access token pair.
   */
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
  ): Promise<OAuthTokens> {
    const response = await fetch(`${BACKEND_URL}/api/v1/mcp-oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: client.client_id,
        scopes: scopes || [],
      }),
    });

    if (!response.ok) {
      const errBody = await response.text();
      throw new Error(`Token refresh failed: ${response.status} ${errBody}`);
    }

    const data = await response.json() as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    return {
      access_token: data.access_token,
      token_type: 'Bearer',
      expires_in: data.expires_in || ACCESS_TOKEN_TTL_S,
      refresh_token: data.refresh_token,
    };
  }

  /**
   * Verifies an access token and returns auth info.
   * Supports both OAuth JWT tokens (from this flow) and legacy API keys.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    // Check if this is a legacy API key (starts with shrike_ or sk_)
    if (isApiKey(token)) {
      return this.verifyApiKey(token);
    }

    // OAuth JWT token — validate against the backend
    const response = await fetch(`${BACKEND_URL}/api/v1/mcp-oauth/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      throw new Error('Invalid or expired access token');
    }

    const data = await response.json() as {
      customer_id: string;
      client_id: string;
      scopes: string[];
      expires_at: number;
      tier: string;
    };

    return {
      token,
      clientId: data.client_id,
      scopes: data.scopes || [],
      expiresAt: data.expires_at,
      extra: {
        customerId: data.customer_id,
        tier: data.tier,
      },
    };
  }

  /**
   * Revokes an access or refresh token.
   */
  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest,
  ): Promise<void> {
    try {
      await fetch(`${BACKEND_URL}/api/v1/mcp-oauth/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: request.token,
          token_type_hint: request.token_type_hint,
        }),
      });
    } catch {
      // Token revocation should not throw per spec — silently ignore errors
    }
  }

  // ─── Internal Helpers ───────────────────────────────────────────────────

  /**
   * Verifies a legacy API key via the existing validation endpoint.
   * This ensures backwards compatibility — existing users with API keys
   * can still authenticate without going through the OAuth flow.
   */
  private async verifyApiKey(apiKey: string): Promise<AuthInfo> {
    const result = await validateApiKey(apiKey);
    if (!result.valid) {
      throw new Error(result.error || 'Invalid API key');
    }

    return {
      token: apiKey,
      clientId: 'legacy-api-key',
      scopes: ['shrike:scan', 'shrike:read'],
      extra: {
        customerId: result.customerId,
        tier: result.tier,
      },
    };
  }

  /**
   * Creates an authorization code after the user has authenticated
   * via the backend OAuth flow. Called by the /oauth/callback handler.
   */
  createAuthorizationCode(params: {
    clientId: string;
    customerId: string;
    codeChallenge: string;
    redirectUri: string;
    scopes: string[];
  }): string {
    return this.authCodes.create(params);
  }

  destroy(): void {
    this.authCodes.destroy();
  }
}

// ─── Utilities ──────────────────────────────────────────────────────────────

/**
 * Returns true if the token looks like a Shrike API key rather than an OAuth JWT.
 */
export function isApiKey(token: string): boolean {
  return token.startsWith('shrike_') || token.startsWith('sk_');
}
