import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AuthorizationCodeStore, ClientStore } from './store.js';

// ---------------------------------------------------------------------------
// AuthorizationCodeStore
// ---------------------------------------------------------------------------

describe('AuthorizationCodeStore', () => {
  let store: AuthorizationCodeStore;

  beforeEach(() => {
    store = new AuthorizationCodeStore();
  });

  afterEach(() => {
    store.destroy();
  });

  it('creates and consumes an authorization code', () => {
    const code = store.create({
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge-abc',
      redirectUri: 'https://example.com/callback',
      scopes: ['shrike:scan'],
    });

    expect(code).toBeTypeOf('string');
    expect(code.length).toBe(64); // 32 bytes hex

    const entry = store.consume(code);
    expect(entry).toBeDefined();
    expect(entry!.clientId).toBe('client-1');
    expect(entry!.customerId).toBe('cust-1');
    expect(entry!.codeChallenge).toBe('challenge-abc');
    expect(entry!.redirectUri).toBe('https://example.com/callback');
    expect(entry!.scopes).toEqual(['shrike:scan']);
  });

  it('consumes a code only once (single-use)', () => {
    const code = store.create({
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge',
      redirectUri: 'https://example.com/callback',
      scopes: [],
    });

    const first = store.consume(code);
    expect(first).toBeDefined();

    const second = store.consume(code);
    expect(second).toBeUndefined();
  });

  it('returns undefined for unknown code', () => {
    expect(store.consume('nonexistent-code')).toBeUndefined();
  });

  it('peek returns entry without consuming it', () => {
    const code = store.create({
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge',
      redirectUri: 'https://example.com/callback',
      scopes: [],
    });

    const peeked = store.peek(code);
    expect(peeked).toBeDefined();
    expect(peeked!.clientId).toBe('client-1');

    // Code should still be consumable
    const consumed = store.consume(code);
    expect(consumed).toBeDefined();
  });

  it('peek returns undefined for unknown code', () => {
    expect(store.peek('nonexistent')).toBeUndefined();
  });

  it('expires codes after TTL', () => {
    vi.useFakeTimers();

    const code = store.create({
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge',
      redirectUri: 'https://example.com/callback',
      scopes: [],
    });

    // Code should be valid immediately
    expect(store.peek(code)).toBeDefined();

    // Advance past the 10-minute TTL
    vi.advanceTimersByTime(11 * 60 * 1000);

    // Code should now be expired
    expect(store.consume(code)).toBeUndefined();
    expect(store.peek(code)).toBeUndefined();

    vi.useRealTimers();
  });

  it('creates unique codes for each call', () => {
    const entry = {
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge',
      redirectUri: 'https://example.com/callback',
      scopes: [],
    };

    const code1 = store.create(entry);
    const code2 = store.create(entry);
    expect(code1).not.toBe(code2);
  });

  it('destroy clears all codes', () => {
    const code = store.create({
      clientId: 'client-1',
      customerId: 'cust-1',
      codeChallenge: 'challenge',
      redirectUri: 'https://example.com/callback',
      scopes: [],
    });

    store.destroy();
    expect(store.consume(code)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// ClientStore
// ---------------------------------------------------------------------------

describe('ClientStore', () => {
  let store: ClientStore;

  beforeEach(() => {
    store = new ClientStore();
  });

  it('registers a client with auto-generated ID and secret', async () => {
    const registered = await store.registerClient({
      redirect_uris: [new URL('https://example.com/callback')],
      client_name: 'Test Client',
      client_secret: undefined,
      client_secret_expires_at: 0,
    });

    expect(registered.client_id).toBeTypeOf('string');
    expect(registered.client_id.length).toBeGreaterThan(0);
    expect(registered.client_secret).toBeTypeOf('string');
    expect(registered.client_secret!.length).toBe(64); // 32 bytes hex
    expect(registered.client_name).toBe('Test Client');
    expect(registered.client_id_issued_at).toBeTypeOf('number');
    expect(registered.client_secret_expires_at).toBe(0);
  });

  it('retrieves a registered client by ID', async () => {
    const registered = await store.registerClient({
      redirect_uris: [new URL('https://example.com/callback')],
      client_name: 'Claude',
      client_secret: undefined,
      client_secret_expires_at: 0,
    });

    const retrieved = await store.getClient(registered.client_id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.client_id).toBe(registered.client_id);
    expect(retrieved!.client_name).toBe('Claude');
  });

  it('returns undefined for unknown client ID', async () => {
    const result = await store.getClient('nonexistent-id');
    expect(result).toBeUndefined();
  });

  it('registers multiple clients independently', async () => {
    const client1 = await store.registerClient({
      redirect_uris: [new URL('https://one.com/callback')],
      client_name: 'Client One',
      client_secret: undefined,
      client_secret_expires_at: 0,
    });

    const client2 = await store.registerClient({
      redirect_uris: [new URL('https://two.com/callback')],
      client_name: 'Client Two',
      client_secret: undefined,
      client_secret_expires_at: 0,
    });

    expect(client1.client_id).not.toBe(client2.client_id);
    expect(client1.client_secret).not.toBe(client2.client_secret);

    const retrieved1 = await store.getClient(client1.client_id);
    const retrieved2 = await store.getClient(client2.client_id);
    expect(retrieved1!.client_name).toBe('Client One');
    expect(retrieved2!.client_name).toBe('Client Two');
  });

  it('preserves redirect_uris from registration', async () => {
    const uris = [
      new URL('https://example.com/callback'),
      new URL('https://example.com/alt-callback'),
    ];

    const registered = await store.registerClient({
      redirect_uris: uris,
      client_secret: undefined,
      client_secret_expires_at: 0,
    });

    expect(registered.redirect_uris).toHaveLength(2);
  });
});
