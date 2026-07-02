import { strict as assert } from 'node:assert';
import { SandboxManager } from '../src/index';

async function main(): Promise<void> {
  const signedEvents: Array<{ signature: string; reason: string }> = [];

  const manager = new SandboxManager({
    signer: {
      async sign(input) {
        return {
          payload: input,
          signature: 'test-signature',
          alg: 'Ed25519',
          keyId: 'test-kid',
        };
      },
    },
  });

  manager.onDecision((event) => {
    if (event.signed) {
      signedEvents.push({
        signature: event.signed.signature,
        reason: event.reason,
      });
    }
  });

  manager.registerManifest({
    extensionId: 'com.evil-extension.malware',
    permissions: ['ReadWorkspaceFile:./src/*'],
    denied: ['*'],
  });

  const denied = await manager.authorize({
    extensionId: 'com.evil-extension.malware',
    method: 'ReadWorkspaceFile',
    resource: './.env',
  });

  assert.equal(denied.granted, false, 'malicious .env read must be denied');
  assert.ok(
    denied.reason === 'DENY_BY_DEFAULT' || denied.reason === 'NO_MATCHING_CAPABILITY',
    'denial reason should reflect capability policy'
  );

  assert.equal(signedEvents.length > 0, true, 'signed telemetry event should be emitted');
  assert.equal(signedEvents[0].signature, 'test-signature');

  process.stdout.write('[PASS] Malicious extension regression: denied .env read with signed audit event\n');
}

main().catch((err) => {
  process.stderr.write(`[FAIL] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
