import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { writeFile, unlink, mkdtemp } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  EnvKeyProvider,
  FileKeyProvider,
  VaultKeyProvider,
  AWSKeyProvider,
  GCPKeyProvider,
  createKeyProvider,
} from './keyProvider.js';

// ---------------------------------------------------------------------------
// EnvKeyProvider
// ---------------------------------------------------------------------------

describe('EnvKeyProvider', () => {
  const originalEnv = process.env.SHRIKE_API_KEY;

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.SHRIKE_API_KEY = originalEnv;
    } else {
      delete process.env.SHRIKE_API_KEY;
    }
  });

  it('returns SHRIKE_API_KEY from env', async () => {
    process.env.SHRIKE_API_KEY = 'shrike_test_key_123';
    const provider = new EnvKeyProvider();
    expect(await provider.getKey()).toBe('shrike_test_key_123');
    expect(provider.name()).toBe('env');
  });

  it('returns null when SHRIKE_API_KEY is not set', async () => {
    delete process.env.SHRIKE_API_KEY;
    const provider = new EnvKeyProvider();
    expect(await provider.getKey()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// FileKeyProvider
// ---------------------------------------------------------------------------

describe('FileKeyProvider', () => {
  let tempDir: string;
  let tempFile: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'shrike-test-'));
    tempFile = join(tempDir, 'api-key');
  });

  afterEach(async () => {
    try {
      await unlink(tempFile);
    } catch {
      // ignore
    }
  });

  it('reads key from file', async () => {
    await writeFile(tempFile, 'shrike_file_key_456\n');
    const provider = new FileKeyProvider(tempFile);
    expect(await provider.getKey()).toBe('shrike_file_key_456');
    expect(provider.name()).toBe('file');
  });

  it('trims whitespace and newlines', async () => {
    await writeFile(tempFile, '  shrike_key  \n\n');
    const provider = new FileKeyProvider(tempFile);
    expect(await provider.getKey()).toBe('shrike_key');
  });

  it('returns null for empty file', async () => {
    await writeFile(tempFile, '');
    const provider = new FileKeyProvider(tempFile);
    expect(await provider.getKey()).toBeNull();
  });

  it('returns null when file does not exist', async () => {
    const provider = new FileKeyProvider('/tmp/nonexistent-shrike-key-file');
    expect(await provider.getKey()).toBeNull();
  });

  it('detects key rotation when file changes', async () => {
    await writeFile(tempFile, 'key_v1');
    const provider = new FileKeyProvider(tempFile);
    expect(await provider.getKey()).toBe('key_v1');

    await writeFile(tempFile, 'key_v2');
    expect(await provider.getKey()).toBe('key_v2');
  });
});

// ---------------------------------------------------------------------------
// VaultKeyProvider
// ---------------------------------------------------------------------------

describe('VaultKeyProvider', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.VAULT_ADDR;
    delete process.env.VAULT_TOKEN;
    delete process.env.VAULT_SECRET_PATH;
    delete process.env.VAULT_SECRET_KEY;
  });

  it('fetches key from Vault KV v2', async () => {
    process.env.VAULT_ADDR = 'http://vault.test:8200';
    process.env.VAULT_TOKEN = 'hvs.test-token';
    process.env.VAULT_SECRET_PATH = 'secret/data/myapp';
    process.env.VAULT_SECRET_KEY = 'shrike_key';

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        data: { data: { shrike_key: 'shrike_from_vault' } },
      }),
    }) as unknown as typeof fetch;

    const provider = new VaultKeyProvider();
    expect(await provider.getKey()).toBe('shrike_from_vault');
    expect(provider.name()).toBe('vault');

    expect(globalThis.fetch).toHaveBeenCalledWith(
      'http://vault.test:8200/v1/secret/data/myapp',
      { headers: { 'X-Vault-Token': 'hvs.test-token' } },
    );
  });

  it('returns null when VAULT_TOKEN is not set', async () => {
    delete process.env.VAULT_TOKEN;
    const provider = new VaultKeyProvider();
    expect(await provider.getKey()).toBeNull();
  });

  it('returns null on Vault 403', async () => {
    process.env.VAULT_TOKEN = 'bad-token';
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
    }) as unknown as typeof fetch;

    const provider = new VaultKeyProvider();
    expect(await provider.getKey()).toBeNull();
  });

  it('returns null on Vault network error', async () => {
    process.env.VAULT_TOKEN = 'some-token';
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch;

    const provider = new VaultKeyProvider();
    expect(await provider.getKey()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AWSKeyProvider (mock dynamic import)
// ---------------------------------------------------------------------------

describe('AWSKeyProvider', () => {
  it('returns null with helpful message when SDK not installed', async () => {
    const provider = new AWSKeyProvider();
    // Dynamic import will fail since @aws-sdk/client-secrets-manager isn't installed
    const result = await provider.getKey();
    expect(result).toBeNull();
    expect(provider.name()).toBe('aws');
  });
});

// ---------------------------------------------------------------------------
// GCPKeyProvider (mock dynamic import)
// ---------------------------------------------------------------------------

describe('GCPKeyProvider', () => {
  it('returns null with helpful message when SDK not installed', async () => {
    const provider = new GCPKeyProvider();
    // Dynamic import will fail since @google-cloud/secret-manager isn't installed
    const result = await provider.getKey();
    expect(result).toBeNull();
    expect(provider.name()).toBe('gcp');
  });
});

// ---------------------------------------------------------------------------
// createKeyProvider factory
// ---------------------------------------------------------------------------

describe('createKeyProvider', () => {
  const originalProvider = process.env.SHRIKE_KEY_PROVIDER;
  const originalKeyFile = process.env.SHRIKE_KEY_FILE;

  afterEach(() => {
    if (originalProvider !== undefined) {
      process.env.SHRIKE_KEY_PROVIDER = originalProvider;
    } else {
      delete process.env.SHRIKE_KEY_PROVIDER;
    }
    if (originalKeyFile !== undefined) {
      process.env.SHRIKE_KEY_FILE = originalKeyFile;
    } else {
      delete process.env.SHRIKE_KEY_FILE;
    }
  });

  it('defaults to EnvKeyProvider when not set', () => {
    delete process.env.SHRIKE_KEY_PROVIDER;
    const provider = createKeyProvider();
    expect(provider.name()).toBe('env');
  });

  it('creates EnvKeyProvider for "env"', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'env';
    expect(createKeyProvider().name()).toBe('env');
  });

  it('creates FileKeyProvider for "file"', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'file';
    expect(createKeyProvider().name()).toBe('file');
  });

  it('creates VaultKeyProvider for "vault"', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'vault';
    expect(createKeyProvider().name()).toBe('vault');
  });

  it('creates AWSKeyProvider for "aws"', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'aws';
    expect(createKeyProvider().name()).toBe('aws');
  });

  it('creates GCPKeyProvider for "gcp"', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'gcp';
    expect(createKeyProvider().name()).toBe('gcp');
  });

  it('falls back to env for unknown provider', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'unknown_provider';
    const provider = createKeyProvider();
    expect(provider.name()).toBe('env');
  });

  it('is case-insensitive', () => {
    process.env.SHRIKE_KEY_PROVIDER = 'VAULT';
    expect(createKeyProvider().name()).toBe('vault');
  });
});
