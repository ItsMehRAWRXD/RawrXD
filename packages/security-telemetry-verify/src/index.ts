export { InMemoryNonceStore, TelemetryVerifier, type TelemetryVerifierOptions } from './verifier';
export {
  createRemoteJwksKeyResolver,
  RemoteJwksKeyResolver,
  type RemoteJwksKeyResolverOptions,
  StaticKeyResolver,
} from './resolver';
export { exportRawPublicKey, generateEd25519KeyPair, signTelemetryPayload } from './signer';

export type {
  FreshnessPolicy,
  JwksLikeDocument,
  JwksLikeKey,
  KeyResolver,
  NonceStore,
  SignatureAlgorithm,
  SignedTelemetryEvent,
  TelemetryPayload,
  VerifyFailureReason,
  VerifyResult,
} from './types';