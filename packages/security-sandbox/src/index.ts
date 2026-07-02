export { CapabilityValidator } from './capability-validator';
export { ProcessBroker } from './process-broker';
export { SandboxManager } from './sandbox-manager';
export { ExtensionBroker } from './broker';
export { Capability, calculateCapsMask, hasCapability } from './capabilities';
export { ToolchainRegistry } from './toolchain-registry';
export {
  validateToolchainManifest,
  type ToolchainManifest,
  type RuntimeLimits,
  type CapabilityAllowlist,
  type ToolchainValidationResult,
} from './toolchain-manifest';

export type {
  BrokerDecision,
  BrokerDecisionSigner,
  BrokerRequestContext,
  CapabilityManifest,
  DecisionListener,
  ExtensionRuntimeSpec,
  SignedBrokerDecision,
} from './types';

export type { SpawnResult } from './broker';
export type { SpawnedExtension } from './process-broker';
