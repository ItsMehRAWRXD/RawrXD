# @rawrxd/security-sandbox

Out-of-process extension sandbox manager with brokered capabilities.

## MVP Components

- `ProcessBroker`: spawn/terminate/supervise extension processes with isolated env.
- `CapabilityValidator`: allow/deny by extension `capabilities.json` style manifest.
- `SandboxManager`: policy gate + signed decision event emission hook.

## Example

```ts
import { SandboxManager } from '@rawrxd/security-sandbox';

const manager = new SandboxManager();

manager.registerManifest({
  extensionId: 'com.safe.readonly',
  permissions: ['ReadWorkspaceFile:./src/*'],
  denied: ['*']
});

const decision = await manager.authorize({
  extensionId: 'com.safe.readonly',
  method: 'ReadWorkspaceFile',
  resource: './src/index.ts'
});
```
