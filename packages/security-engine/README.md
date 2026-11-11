# @rawrxd/security-engine

Framework-agnostic security-as-code engine for request-time decisions.

## Features

- Declarative rule DSL (`rateLimit`, `botProtection`, `piiMasking`)
- Fail-open strategy by default
- Pluggable state provider for distributed counters
- Decision telemetry hook (`onDecision`)

## Quick Start

```ts
import { SecuritySDK } from '@rawrxd/security-engine';

const security = new SecuritySDK({
  rules: {
    rateLimit: { window: '1m', max: 100, keyBy: 'ip' },
    botProtection: { block: true },
    piiMasking: { enabled: true }
  },
  failOpen: true
});

security.onDecision((event) => {
  console.log('security decision', event.decision.reason, event.decision.action);
});

const decision = await security.evaluate({
  method: 'POST',
  path: '/api/chat',
  ip: '203.0.113.10',
  headers: { 'user-agent': 'Mozilla/5.0' },
  payload: { email: 'user@example.com', token: 'abc' }
});
```

## Signed Decisions

You can inject a telemetry signer to produce verifiable decision artifacts.

```ts
import type { TelemetrySigner } from '@rawrxd/security-engine';

const signer: TelemetrySigner = {
  validateKey() {
    // validate key material on startup
  },
  async sign(input) {
    // return detached Ed25519 signature envelope
    return {
      payload: input,
      signature: 'base64url-signature',
      alg: 'Ed25519',
      keyId: 'key-1'
    };
  }
};

const security = new SecuritySDK({
  rules: { rateLimit: { window: '1m', max: 100 } },
  telemetry: {
    signer,
    asyncSigning: true
  }
});

// Explicitly sign a decision (useful for adapters adding headers).
const signed = await security.signDecision(decision);

// Receive non-blocking signed events off the hot path.
security.onSignedDecision((event) => {
  console.log(event.signedPayload.signature);
});
```

## State Provider

For global/distributed rate limiting, implement `StateProvider`:

```ts
import type { StateProvider } from '@rawrxd/security-engine';

class RedisStateProvider implements StateProvider {
  async incrementCounter(key: string, windowMs: number): Promise<number> {
    // implement atomic increment + TTL in Redis
    return 1;
  }
}
```