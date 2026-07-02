import {
  type FreshnessPolicy,
  type KeyResolver,
  type NonceStore,
  type SignedTelemetryEvent,
  type VerifyResult,
} from './types';
import { canonicalSerialize, decodeBase64Url } from './utils';

const DEFAULT_POLICY: FreshnessPolicy = {
  maxClockSkewMs: 5 * 60 * 1000,
  nonceTtlMs: 10 * 60 * 1000,
};

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export class InMemoryNonceStore implements NonceStore {
  private data = new Map<string, number>();

  public async has(nonce: string): Promise<boolean> {
    this.prune();
    const expiresAt = this.data.get(nonce);
    return typeof expiresAt === 'number' && expiresAt > Date.now();
  }

  public async set(nonce: string, ttlMs: number): Promise<void> {
    this.prune();
    this.data.set(nonce, Date.now() + ttlMs);
  }

  private prune(): void {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.data.entries()) {
      if (expiresAt <= now) {
        this.data.delete(nonce);
      }
    }
  }
}

export interface TelemetryVerifierOptions {
  policy?: Partial<FreshnessPolicy>;
  nonceStore?: NonceStore;
  enforceLifecyclePolicy?: boolean;
}

export class TelemetryVerifier {
  private readonly policy: FreshnessPolicy;
  private readonly nonceStore: NonceStore;
  private readonly enforceLifecyclePolicy: boolean;

  constructor(options: TelemetryVerifierOptions = {}) {
    this.policy = {
      ...DEFAULT_POLICY,
      ...options.policy,
    };
    this.nonceStore = options.nonceStore ?? new InMemoryNonceStore();
    this.enforceLifecyclePolicy = options.enforceLifecyclePolicy ?? true;
  }

  public async verify(event: SignedTelemetryEvent, publicKey: Uint8Array): Promise<boolean> {
    const result = await this.verifyDetailed(event, publicKey);
    return result.valid;
  }

  public async verifyWithResolver(event: SignedTelemetryEvent, resolver: KeyResolver): Promise<boolean> {
    const result = await this.verifyDetailedWithResolver(event, resolver);
    return result.valid;
  }

  public async verifyDetailed(
    event: SignedTelemetryEvent,
    publicKey: Uint8Array
  ): Promise<VerifyResult> {
    if (event.alg !== 'Ed25519') {
      return { valid: false, reason: 'INVALID_ALGORITHM' };
    }

    if (!globalThis.crypto?.subtle) {
      return { valid: false, reason: 'CRYPTO_UNAVAILABLE' };
    }

    if (!publicKey || publicKey.length !== 32) {
      return { valid: false, reason: 'INVALID_PUBLIC_KEY' };
    }

    const now = Date.now();
    const age = Math.abs(now - event.payload.timestamp);
    if (age > this.policy.maxClockSkewMs) {
      return { valid: false, reason: 'TIMESTAMP_OUT_OF_WINDOW' };
    }

    const nonceSeen = await this.nonceStore.has(event.payload.nonce);
    if (nonceSeen) {
      return { valid: false, reason: 'REPLAY_NONCE' };
    }

    let signatureBytes: Uint8Array;
    try {
      signatureBytes = decodeBase64Url(event.signature);
    } catch {
      return { valid: false, reason: 'INVALID_SIGNATURE_ENCODING' };
    }

    const payloadBytes = new TextEncoder().encode(canonicalSerialize(event.payload));

    let key: CryptoKey;
    try {
      key = await globalThis.crypto.subtle.importKey(
        'raw',
        toArrayBuffer(publicKey),
        { name: 'Ed25519' },
        false,
        ['verify']
      );
    } catch {
      return { valid: false, reason: 'INVALID_PUBLIC_KEY' };
    }

    const verified = await globalThis.crypto.subtle.verify(
      'Ed25519',
      key,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(payloadBytes)
    );

    if (!verified) {
      return { valid: false, reason: 'SIGNATURE_MISMATCH' };
    }

    await this.nonceStore.set(event.payload.nonce, this.policy.nonceTtlMs);
    return { valid: true };
  }

  public async verifyDetailedWithResolver(
    event: SignedTelemetryEvent,
    resolver: KeyResolver
  ): Promise<VerifyResult> {
    if (!event.keyId) {
      return { valid: false, reason: 'KEY_ID_REQUIRED' };
    }

    let entry = await resolver.resolveEntry(event.keyId);
    if (!entry) {
      try {
        await resolver.refresh();
      } catch {
        return { valid: false, reason: 'KEY_RESOLVER_ERROR' };
      }
      entry = await resolver.resolveEntry(event.keyId);
      if (!entry) {
        const fallbackKey = await resolver.resolve(event.keyId);
        if (!fallbackKey) {
          return { valid: false, reason: 'KEY_NOT_FOUND' };
        }
        if (this.enforceLifecyclePolicy) {
          return { valid: false, reason: 'KEY_METADATA_REQUIRED' };
        }
        return this.verifyDetailed(event, fallbackKey);
      }
    }

    const eventTs = event.payload.timestamp;
    if (this.enforceLifecyclePolicy) {
      if (typeof entry.nbf === 'number' && eventTs < entry.nbf) {
        return { valid: false, reason: 'KEY_NOT_YET_VALID' };
      }
      if (typeof entry.exp === 'number' && eventTs > entry.exp) {
        return { valid: false, reason: 'KEY_EXPIRED' };
      }
      if (typeof entry.exp !== 'number') {
        return { valid: false, reason: 'KEY_METADATA_REQUIRED' };
      }
    }

    if (!entry.publicKey) {
      return { valid: false, reason: 'KEY_NOT_FOUND' };
    }

    return this.verifyDetailed(event, entry.publicKey);
  }
}