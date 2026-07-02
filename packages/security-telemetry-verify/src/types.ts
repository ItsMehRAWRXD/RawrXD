export type SignatureAlgorithm = 'Ed25519';

export interface TelemetryPayload {
  timestamp: number;
  nonce: string;
  eventType: string;
  sdkInstanceId?: string;
  data: Record<string, unknown>;
}

export interface SignedTelemetryEvent {
  payload: TelemetryPayload;
  signature: string; // Base64URL detached signature
  alg: SignatureAlgorithm;
  keyId?: string;
}

export interface KeyResolver {
  resolve(keyId: string): Promise<Uint8Array | null>;
  resolveEntry(keyId: string): Promise<ResolvedKeyEntry | null>;
  refresh(): Promise<void>;
}

export interface ResolvedKeyEntry {
  keyId: string;
  publicKey: Uint8Array;
  nbf?: number; // epoch milliseconds
  exp?: number; // epoch milliseconds
}

export interface JwksLikeKey {
  kid: string;
  kty: 'OKP';
  crv: 'Ed25519';
  x: string; // Base64URL public key
  use?: 'sig';
  alg?: 'EdDSA';
  nbf?: number; // epoch milliseconds
  exp?: number; // epoch milliseconds
}

export interface JwksLikeDocument {
  keys: JwksLikeKey[];
}

export interface FreshnessPolicy {
  maxClockSkewMs: number;
  nonceTtlMs: number;
}

export interface NonceStore {
  has(nonce: string): Promise<boolean>;
  set(nonce: string, ttlMs: number): Promise<void>;
}

export type VerifyFailureReason =
  | 'INVALID_ALGORITHM'
  | 'INVALID_SIGNATURE_ENCODING'
  | 'INVALID_PUBLIC_KEY'
  | 'SIGNATURE_MISMATCH'
  | 'TIMESTAMP_OUT_OF_WINDOW'
  | 'REPLAY_NONCE'
  | 'CRYPTO_UNAVAILABLE'
  | 'KEY_ID_REQUIRED'
  | 'KEY_NOT_FOUND'
  | 'KEY_RESOLVER_ERROR'
  | 'KEY_METADATA_REQUIRED'
  | 'KEY_NOT_YET_VALID'
  | 'KEY_EXPIRED';

export interface VerifyResult {
  valid: boolean;
  reason?: VerifyFailureReason;
}