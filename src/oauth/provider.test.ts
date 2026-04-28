import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ShrikeOAuthProvider, isApiKey } from './provider.js';

// Mock the config module
vi.mock('../config.js', () => ({
  config: {
    backendUrl: 'https://mock-backend.test',
    apiKey: null,
    port: 8000,
    debug: false,
  },
}));

// Mock the auth module
vi.mock('../auth.js', () => ({
  validateApiKey: vi.fn(async (key: string) => {
    if (key === 'shrike_valid_key') {
      return { valid: true, customerId: 'cust-123', tier: 'enterprise' };
    }
    return { valid: false, error: 'Invalid key' };
  }),
}));

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('ShrikeOAuthProvider', () => {
  let provider: ShrikeOAuthProvider;

  beforeEach(() => {
    provider = new ShrikeOAuthProvider();
    mockFetch.mockReset();
  });

  afterEach(() => {
    provider.destroy();
  });

  // ─── clientsStore ───────────────────────────────────────────────────

  describe('clientsStore', () => {
    it('provides a working client store', () => {
      expect(provider.clientsStore).toBeDefined();
    });

    it('supports dynamic client registration', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_name: 'Claude',
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      expect(client.client_id).toBeTruthy();

      const retrieved = await provider.clientsStore.getClient(client.client_id);
      expect(retrieved).toBeDefined();
      expect(retrieved!.client_name).toBe('Claude');
    });
  });

  // ─── createAuthorizationCode + challengeForAuthorizationCode ──────

  describe('authorization codes', () => {
    it('creates a code and retrieves its challenge', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      const code = provider.createAuthorizationCode({
        clientId: client.client_id,
        customerId: 'cust-123',
        codeChallenge: 'S256-challenge-value',
        redirectUri: 'https://claude.ai/callback',
        scopes: ['shrike:scan'],
      });

      const challenge = await provider.challengeForAuthorizationCode(client, code);
      expect(challenge).toBe('S256-challenge-value');
    });

    it('throws for invalid authorization code', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      await expect(
        provider.challengeForAuthorizationCode(client, 'invalid-code')
      ).rejects.toThrow('Invalid or expired authorization code');
    });
  });

  // ─── exchangeAuthorizationCode ────────────────────────────────────

  describe('exchangeAuthorizationCode', () => {
    it('exchanges code for tokens via backend', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      const code = provider.createAuthorizationCode({
        clientId: client.client_id,
        customerId: 'cust-123',
        codeChallenge: 'challenge',
        redirectUri: 'https://claude.ai/callback',
        scopes: ['shrike:scan'],
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'jwt-access-token',
          refresh_token: 'jwt-refresh-token',
          expires_in: 3600,
        }),
      });

      const tokens = await provider.exchangeAuthorizationCode(client, code);

      expect(tokens.access_token).toBe('jwt-access-token');
      expect(tokens.refresh_token).toBe('jwt-refresh-token');
      expect(tokens.token_type).toBe('Bearer');
      expect(tokens.expires_in).toBe(3600);

      // Verify correct backend call
      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/mcp-oauth/token',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"grant_type":"authorization_code"'),
        }),
      );
    });

    it('throws for invalid code', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      await expect(
        provider.exchangeAuthorizationCode(client, 'bad-code')
      ).rejects.toThrow('Invalid or expired authorization code');
    });

    it('throws for client ID mismatch', async () => {
      const client1 = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      const client2 = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://other.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      const code = provider.createAuthorizationCode({
        clientId: client1.client_id,
        customerId: 'cust-123',
        codeChallenge: 'challenge',
        redirectUri: 'https://claude.ai/callback',
        scopes: [],
      });

      await expect(
        provider.exchangeAuthorizationCode(client2, code)
      ).rejects.toThrow('Client ID mismatch');
    });

    it('throws when backend returns error', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      const code = provider.createAuthorizationCode({
        clientId: client.client_id,
        customerId: 'cust-123',
        codeChallenge: 'challenge',
        redirectUri: 'https://claude.ai/callback',
        scopes: [],
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: async () => 'Internal server error',
      });

      await expect(
        provider.exchangeAuthorizationCode(client, code)
      ).rejects.toThrow('Token exchange failed');
    });
  });

  // ─── exchangeRefreshToken ─────────────────────────────────────────

  describe('exchangeRefreshToken', () => {
    it('refreshes tokens via backend', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'new-access-token',
          refresh_token: 'new-refresh-token',
          expires_in: 3600,
        }),
      });

      const tokens = await provider.exchangeRefreshToken(
        client,
        'old-refresh-token',
        ['shrike:scan'],
      );

      expect(tokens.access_token).toBe('new-access-token');
      expect(tokens.refresh_token).toBe('new-refresh-token');
      expect(tokens.token_type).toBe('Bearer');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/mcp-oauth/token',
        expect.objectContaining({
          body: expect.stringContaining('"grant_type":"refresh_token"'),
        }),
      );
    });

    it('throws when backend returns error', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: async () => 'Expired',
      });

      await expect(
        provider.exchangeRefreshToken(client, 'expired-token')
      ).rejects.toThrow('Token refresh failed');
    });
  });

  // ─── verifyAccessToken ────────────────────────────────────────────

  describe('verifyAccessToken', () => {
    it('verifies a legacy API key', async () => {
      const authInfo = await provider.verifyAccessToken('shrike_valid_key');

      expect(authInfo.token).toBe('shrike_valid_key');
      expect(authInfo.clientId).toBe('legacy-api-key');
      expect(authInfo.scopes).toEqual(['shrike:scan', 'shrike:read']);
      expect(authInfo.extra?.['customerId']).toBe('cust-123');
      expect(authInfo.extra?.['tier']).toBe('enterprise');
    });

    it('throws for invalid API key', async () => {
      await expect(
        provider.verifyAccessToken('shrike_invalid_key')
      ).rejects.toThrow('Invalid key');
    });

    it('verifies an OAuth JWT token via backend', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          customer_id: 'cust-456',
          client_id: 'mcp-client-1',
          scopes: ['shrike:scan'],
          expires_at: 1700000000,
          tier: 'pro',
        }),
      });

      const authInfo = await provider.verifyAccessToken('eyJhbGciOiJIUzI1NiJ9.jwt-token');

      expect(authInfo.token).toBe('eyJhbGciOiJIUzI1NiJ9.jwt-token');
      expect(authInfo.clientId).toBe('mcp-client-1');
      expect(authInfo.scopes).toEqual(['shrike:scan']);
      expect(authInfo.extra?.['customerId']).toBe('cust-456');
      expect(authInfo.extra?.['tier']).toBe('pro');

      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/mcp-oauth/verify',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.jwt-token',
          }),
        }),
      );
    });

    it('throws when OAuth JWT verification fails', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      await expect(
        provider.verifyAccessToken('eyJhbGciOiJIUzI1NiJ9.invalid')
      ).rejects.toThrow('Invalid or expired access token');
    });

    it('routes sk_ prefix keys to API key validation', async () => {
      await expect(
        provider.verifyAccessToken('sk_agent_invalid')
      ).rejects.toThrow('Invalid key');
    });
  });

  // ─── revokeToken ──────────────────────────────────────────────────

  describe('revokeToken', () => {
    it('calls backend revocation endpoint', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      mockFetch.mockResolvedValueOnce({ ok: true });

      // Should not throw
      await provider.revokeToken(client, {
        token: 'some-token',
        token_type_hint: 'refresh_token',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://mock-backend.test/api/v1/mcp-oauth/revoke',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"token":"some-token"'),
        }),
      );
    });

    it('silently handles revocation errors', async () => {
      const client = await provider.clientsStore.registerClient!({
        redirect_uris: [new URL('https://claude.ai/callback')],
        client_secret: undefined,
        client_secret_expires_at: 0,
      });

      mockFetch.mockRejectedValueOnce(new Error('network error'));

      // Should not throw per RFC 7009
      await provider.revokeToken(client, {
        token: 'some-token',
      });
    });
  });
});

// ---------------------------------------------------------------------------
// isApiKey
// ---------------------------------------------------------------------------

describe('isApiKey', () => {
  it('returns true for shrike_ prefixed tokens', () => {
    expect(isApiKey('shrike_abc123')).toBe(true);
    expect(isApiKey('shrike_habiru_ent_2026')).toBe(true);
  });

  it('returns true for sk_ prefixed tokens', () => {
    expect(isApiKey('sk_cust_abc123')).toBe(true);
    expect(isApiKey('sk_agent_def456')).toBe(true);
  });

  it('returns false for JWT tokens', () => {
    expect(isApiKey('eyJhbGciOiJIUzI1NiJ9.payload.signature')).toBe(false);
  });

  it('returns false for random strings', () => {
    expect(isApiKey('some-random-token')).toBe(false);
    expect(isApiKey('')).toBe(false);
  });
});
