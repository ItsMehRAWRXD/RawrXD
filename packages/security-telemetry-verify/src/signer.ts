import type { SignedTelemetryEvent, TelemetryPayload } from './types';
import { canonicalSerialize, encodeBase64Url } from './utils';

export async function signTelemetryPayload(
  payload: TelemetryPayload,
  privateKey: CryptoKey,
  keyId?: string
): Promise<SignedTelemetryEvent> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API unavailable');
  }

  const payloadBytes = new TextEncoder().encode(canonicalSerialize(payload));
  const signature = await globalThis.crypto.subtle.sign('Ed25519', privateKey, payloadBytes);
  const signatureBytes = new Uint8Array(signature);

  return {
    payload,
    signature: encodeBase64Url(signatureBytes),
    alg: 'Ed25519',
    keyId,
  };
}

export async function generateEd25519KeyPair(): Promise<CryptoKeyPair> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API unavailable');
  }

  return globalThis.crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );
}

export async function exportRawPublicKey(publicKey: CryptoKey): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto subtle API unavailable');
  }

  const raw = await globalThis.crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}