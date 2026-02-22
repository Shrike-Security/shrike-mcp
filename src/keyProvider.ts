/**
 * KeyProvider — Pluggable API key sourcing for enterprise secret managers.
 *
 * Supports: environment variables (default), files (K8s Secrets), HashiCorp Vault,
 * AWS Secrets Manager, and GCP Secret Manager.
 *
 * Backwards compatible: if SHRIKE_KEY_PROVIDER is not set, behaves identically
 * to the original SHRIKE_API_KEY env var approach.
 */

import { readFile } from 'fs/promises';

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

export interface KeyProvider {
  /** Returns the current API key, or null if not configured */
  getKey(): Promise<string | null>;
  /** Human-readable provider name for logging */
  name(): string;
  /** Optional cleanup (close connections, clear timers) */
  close?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// EnvKeyProvider — default, wraps process.env.SHRIKE_API_KEY
// ---------------------------------------------------------------------------

export class EnvKeyProvider implements KeyProvider {
  async getKey(): Promise<string | null> {
    return process.env.SHRIKE_API_KEY || null;
  }
  name(): string {
    return 'env';
  }
}

// ---------------------------------------------------------------------------
// FileKeyProvider — reads key from a file (K8s Secrets volume mount)
// ---------------------------------------------------------------------------

export class FileKeyProvider implements KeyProvider {
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
  }

  async getKey(): Promise<string | null> {
    try {
      const content = await readFile(this.filePath, 'utf-8');
      return content.trim() || null;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[FileKeyProvider] Failed to read ${this.filePath}: ${message}`);
      return null;
    }
  }

  name(): string {
    return 'file';
  }
}

// ---------------------------------------------------------------------------
// VaultKeyProvider — HashiCorp Vault HTTP API (KV v2)
// Uses native fetch — zero extra dependencies.
// ---------------------------------------------------------------------------

export class VaultKeyProvider implements KeyProvider {
  private vaultAddr: string;
  private vaultToken: string;
  private secretPath: string;
  private secretKey: string;

  constructor() {
    this.vaultAddr = process.env.VAULT_ADDR || 'http://127.0.0.1:8200';
    this.vaultToken = process.env.VAULT_TOKEN || '';
    this.secretPath = process.env.VAULT_SECRET_PATH || 'secret/data/shrike';
    this.secretKey = process.env.VAULT_SECRET_KEY || 'api_key';
  }

  async getKey(): Promise<string | null> {
    if (!this.vaultToken) {
      console.error('[VaultKeyProvider] VAULT_TOKEN not set');
      return null;
    }
    try {
      const url = `${this.vaultAddr}/v1/${this.secretPath}`;
      const response = await fetch(url, {
        headers: { 'X-Vault-Token': this.vaultToken },
      });
      if (!response.ok) {
        console.error(`[VaultKeyProvider] Vault returned ${response.status}`);
        return null;
      }
      const data = (await response.json()) as {
        data?: { data?: Record<string, string> };
      };
      return data?.data?.data?.[this.secretKey] || null;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[VaultKeyProvider] Failed to fetch from Vault: ${message}`);
      return null;
    }
  }

  name(): string {
    return 'vault';
  }
}

// ---------------------------------------------------------------------------
// AWSKeyProvider — AWS Secrets Manager (dynamic import, optional dep)
// ---------------------------------------------------------------------------

export class AWSKeyProvider implements KeyProvider {
  private secretName: string;
  private secretKey: string;
  private region: string;

  constructor() {
    this.secretName = process.env.AWS_SECRET_NAME || 'shrike/api-key';
    this.secretKey = process.env.AWS_SECRET_KEY || 'api_key';
    this.region = process.env.AWS_REGION || 'us-east-1';
  }

  async getKey(): Promise<string | null> {
    try {
      // Dynamic import via variable to avoid TypeScript module resolution on optional deps
      const moduleName = '@aws-sdk/client-secrets-manager';
      const mod = await import(/* @vite-ignore */ moduleName);
      const { SecretsManagerClient, GetSecretValueCommand } = mod;
      const client = new SecretsManagerClient({ region: this.region });
      const result = await client.send(
        new GetSecretValueCommand({ SecretId: this.secretName }),
      );
      if (result.SecretString) {
        try {
          const parsed = JSON.parse(result.SecretString) as Record<string, string>;
          return parsed[this.secretKey] || null;
        } catch {
          // Not JSON — return raw string as the key
          return result.SecretString.trim() || null;
        }
      }
      return null;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('Cannot find module') || message.includes('MODULE_NOT_FOUND')) {
        console.error(
          '[AWSKeyProvider] @aws-sdk/client-secrets-manager not installed. Run: npm install @aws-sdk/client-secrets-manager',
        );
      } else {
        console.error(`[AWSKeyProvider] Failed to fetch secret: ${message}`);
      }
      return null;
    }
  }

  name(): string {
    return 'aws';
  }
}

// ---------------------------------------------------------------------------
// GCPKeyProvider — GCP Secret Manager (dynamic import, optional dep)
// ---------------------------------------------------------------------------

export class GCPKeyProvider implements KeyProvider {
  private secretName: string;

  constructor() {
    const project = process.env.GCP_PROJECT || '';
    const secret = process.env.GCP_SECRET_NAME || 'shrike-api-key';
    const version = process.env.GCP_SECRET_VERSION || 'latest';
    this.secretName = `projects/${project}/secrets/${secret}/versions/${version}`;
  }

  async getKey(): Promise<string | null> {
    try {
      // Dynamic import via variable to avoid TypeScript module resolution on optional deps
      const moduleName = '@google-cloud/secret-manager';
      const mod = await import(/* @vite-ignore */ moduleName);
      const { SecretManagerServiceClient } = mod;
      const client = new SecretManagerServiceClient();
      const [response] = await client.accessSecretVersion({
        name: this.secretName,
      });
      const payload = response.payload?.data;
      if (!payload) return null;
      const value =
        typeof payload === 'string'
          ? payload
          : Buffer.from(payload as Uint8Array).toString('utf-8');
      return value.trim() || null;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes('Cannot find module') || message.includes('MODULE_NOT_FOUND')) {
        console.error(
          '[GCPKeyProvider] @google-cloud/secret-manager not installed. Run: npm install @google-cloud/secret-manager',
        );
      } else {
        console.error(`[GCPKeyProvider] Failed to fetch secret: ${message}`);
      }
      return null;
    }
  }

  name(): string {
    return 'gcp';
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createKeyProvider(): KeyProvider {
  const provider = (process.env.SHRIKE_KEY_PROVIDER || 'env').toLowerCase();
  switch (provider) {
    case 'env':
      return new EnvKeyProvider();
    case 'file':
      return new FileKeyProvider(
        process.env.SHRIKE_KEY_FILE || '/var/run/secrets/shrike/api-key',
      );
    case 'vault':
      return new VaultKeyProvider();
    case 'aws':
      return new AWSKeyProvider();
    case 'gcp':
      return new GCPKeyProvider();
    default:
      console.error(
        `[KeyProvider] Unknown SHRIKE_KEY_PROVIDER="${provider}", falling back to env`,
      );
      return new EnvKeyProvider();
  }
}
