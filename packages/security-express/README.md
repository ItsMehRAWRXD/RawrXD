# @rawrxd/security-express

Express middleware adapter for `@rawrxd/security-engine`.

## Quick Start

```ts
import express from 'express';
import { SecuritySDK } from '@rawrxd/security-engine';
import { createExpressMiddleware } from '@rawrxd/security-express';

const app = express();
app.use(express.json());

const sdk = new SecuritySDK({
  rules: {
    rateLimit: { window: '1m', max: 100, keyBy: 'ip+path' },
    botProtection: { block: true },
    piiMasking: { enabled: true, fields: ['email', 'token', 'password'] }
  }
});

sdk.onDecision(({ decision }) => {
  console.log(decision.action, decision.reason, decision.context.path);
});

app.use(createExpressMiddleware(sdk, {
  userIdHeader: 'x-user-id',
  blockStatusCode: 403,
  attachDecisionToRequest: true,
  attachSignatureHeaders: true,
  signatureHeaderName: 'X-Governance-Signature'
}));

app.get('/health', (_req, res) => res.json({ ok: true }));
```

## Publish Rotation Keys (.well-known)

```ts
import { createSecurityKeysHandler } from '@rawrxd/security-express';

app.get(
  '/.well-known/security-keys.json',
  createSecurityKeysHandler({
    keys: [
      {
        kid: '2026-06-01',
        kty: 'OKP',
        crv: 'Ed25519',
        x: '<base64url-public-key>',
        use: 'sig',
        alg: 'EdDSA',
        nbf: Date.now() - 60_000,
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000
      }
    ]
  })
);
```

When a request is blocked, middleware returns:

```json
{
  "error": "REQUEST_BLOCKED",
  "reason": "rate_limit_exceeded:101/100",
  "matchedRules": ["rateLimit"]
}
```

When `attachSignatureHeaders` is enabled and a signer is configured in
`@rawrxd/security-engine`, middleware adds:

- `X-Governance-Signature`
- `X-Governance-Signature-Alg`
- `X-Governance-Key-Id` (when available)