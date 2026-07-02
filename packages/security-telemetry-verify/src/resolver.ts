import { decodeBase64Url } from './utils';
import type { JwksLikeDocument, KeyResolver, ResolvedKeyEntry } from './types';

export interface RemoteJwksKeyResolverOptions {
  cacheTtlMs?: number;
  fetchImpl?: typeof fetch;
}

export class StaticKeyResolver implements KeyResolver {
  private readonly keys = new Map<string, ResolvedKeyEntry>();

  constructor(initial: Record<string, Uint8Array | ResolvedKeyEntry> = {}) {
    for (const [keyId, key] of Object.entries(initial)) {
      if (key instanceof Uint8Array) {
        this.keys.set(keyId, { keyId, publicKey: key });
      } else {
        this.keys.set(keyId, {
          keyId,
          publicKey: key.publicKey,
          nbf: key.nbf,
          exp: key.exp,
        });
      }
    }
  }

  public async resolve(keyId: string): Promise<Uint8Array | null> {
    return this.keys.get(keyId)?.publicKey ?? null;
  }

  public async resolveEntry(keyId: string): Promise<ResolvedKeyEntry | null> {
    return this.keys.get(keyId) ?? null;
  }

  public async refresh(): Promise<void> {
    // No-op for static resolver.
  }

  public set(keyId: string, key: Uint8Array, nbf?: number, exp?: number): void {
    this.keys.set(keyId, { keyId, publicKey: key, nbf, exp });
  }
}

export class RemoteJwksKeyResolver implements KeyResolver {
  private readonly url: string;
  private readonly cacheTtlMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly cache = new Map<string, ResolvedKeyEntry>();
  private expiresAt = 0;
  private inflight: Promise<void> | null = null;

  constructor(url: string, options: RemoteJwksKeyResolverOptions = {}) {
    this.url = url;
    this.cacheTtlMs = options.cacheTtlMs ?? 60_000;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  public async resolve(keyId: string): Promise<Uint8Array | null> {
    await this.ensureFresh();
    return this.cache.get(keyId)?.publicKey ?? null;
  }

  public async resolveEntry(keyId: string): Promise<ResolvedKeyEntry | null> {
    await this.ensureFresh();
    return this.cache.get(keyId) ?? null;
  }

  public async refresh(): Promise<void> {
    if (this.inflight) {
      await this.inflight;
      return;
    }

    this.inflight = this.refreshInternal();
    try {
      await this.inflight;
    } finally {
      this.inflight = null;
    }
  }

  private async ensureFresh(): Promise<void> {
    if (Date.now() < this.expiresAt && this.cache.size > 0) {
      return;
    }
    await this.refresh();
  }

  private async refreshInternal(): Promise<void> {
    if (!this.fetchImpl) {
      throw new Error('fetch is unavailable in this runtime');
    }

    const response = await this.fetchImpl(this.url, {
      method: 'GET',
      headers: { accept: 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`JWKS fetch failed: HTTP ${response.status}`);
    }

    const json = (await response.json()) as JwksLikeDocument;
    if (!json || !Array.isArray(json.keys)) {
      throw new Error('Invalid JWKS payload');
    }

    const next = new Map<string, ResolvedKeyEntry>();
    for (const key of json.keys) {
      if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.kid !== 'string') {
        continue;
      }

      try {
        const raw = decodeBase64Url(key.x);
        if (raw.length === 32) {
          next.set(key.kid, {
            keyId: key.kid,
            publicKey: raw,
            nbf: typeof key.nbf === 'number' ? key.nbf : undefined,
            exp: typeof key.exp === 'number' ? key.exp : undefined,
          });
        }
      } catch {
        // Ignore malformed keys and continue with remaining keys.
      }
    }

    this.cache.clear();
    for (const [kid, key] of next.entries()) {
      this.cache.set(kid, key);
    }
    this.expiresAt = Date.now() + this.cacheTtlMs;
  }
}

export function createRemoteJwksKeyResolver(
  url: string,
  options?: RemoteJwksKeyResolverOptions
): RemoteJwksKeyResolver {
  return new RemoteJwksKeyResolver(url, options);
}