# @rawrxd/security-telemetry-verify

Open-core verification package for signed Sovereign telemetry events.

## Contract

- Algorithm: `Ed25519`
- Signature format: detached signature in `Base64URL`
- Signed payload fields must include:
  - `timestamp` (unix epoch ms)
  - `nonce` (unique per event)
  - `eventType`
  - `data`

## Verification API

```ts
import { TelemetryVerifier } from '@rawrxd/security-telemetry-verify';

const verifier = new TelemetryVerifier({
  policy: {
    maxClockSkewMs: 5 * 60 * 1000,
    nonceTtlMs: 10 * 60 * 1000
  }
});

const valid = await verifier.verify(signedEvent, publicKeyBytes);
```

## JWKS Key Rotation (Recommended)

```ts
import {
  createRemoteJwksKeyResolver,
  TelemetryVerifier,
} from '@rawrxd/security-telemetry-verify';

const verifier = new TelemetryVerifier();
const resolver = createRemoteJwksKeyResolver(
  'https://example.com/.well-known/security-keys.json',
  { cacheTtlMs: 60_000 }
);

const valid = await verifier.verifyWithResolver(signedEvent, resolver);
```

When a key ID is unknown, the resolver refreshes from JWKS and retries verification.

## Lifecycle Policy Controls (`nbf` / `exp`)

`JwksLikeKey` supports key validity windows:

- `nbf`: not-before epoch milliseconds
- `exp`: expiry epoch milliseconds

Verifier checks key validity against the event payload timestamp.

Default behavior is strict (`enforceLifecyclePolicy: true`):

- rejects keys with missing lifecycle metadata where strict policy requires it
- rejects events signed before `nbf`
- rejects events signed after `exp`

```ts
const verifier = new TelemetryVerifier({
  enforceLifecyclePolicy: true
});
```

## Detailed Result

```ts
const result = await verifier.verifyDetailed(signedEvent, publicKeyBytes);
if (!result.valid) {
  console.error('verify failed:', result.reason);
}
```

## Dev/Test Signer Helper

This package includes convenience helpers for local testing:

```ts
import {
  exportRawPublicKey,
  generateEd25519KeyPair,
  signTelemetryPayload,
  TelemetryVerifier,
} from '@rawrxd/security-telemetry-verify';

const { privateKey, publicKey } = await generateEd25519KeyPair();
const publicKeyRaw = await exportRawPublicKey(publicKey);

const signed = await signTelemetryPayload(
  {
    timestamp: Date.now(),
    nonce: crypto.randomUUID(),
    eventType: 'TOOL_BLOCKED',
    data: { reason: 'rate_limit_exceeded' }
  },
  privateKey,
  'key-1'
);

const verifier = new TelemetryVerifier();
console.log(await verifier.verify(signed, publicKeyRaw));
```

## Notes

- Verifier is designed to be edge-safe (Web Crypto API).
- Canonical JSON serialization is used before signing and verifying.
- Replay defense is enforced via nonce store + timestamp skew checks.
- For rotated keys, set `keyId` on signed events and publish active keys via JWKS.