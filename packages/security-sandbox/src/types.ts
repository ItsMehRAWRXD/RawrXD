import type { IpcMethod } from '@rawrxd/security-ipc';

export interface CapabilityManifest {
  extensionId: string;
  permissions: string[];
  denied?: string[];
  version?: string;
}

export interface ExtensionRuntimeSpec {
  extensionId: string;
  entryFile: string;
  runtimePath?: string;
  args?: string[];
  workingDirectory?: string;
  allowEnvKeys?: string[];
  lowPriority?: boolean;
  /** Named pipe name injected as RAWRXD_PIPE_NAME env var */
  pipeName?: string;
}

export interface BrokerRequestContext {
  extensionId: string;
  method: IpcMethod | string;
  resource?: string;
}

export interface BrokerDecision {
  granted: boolean;
  reason: string;
}

export interface SignedBrokerDecision {
  payload: {
    timestamp: number;
    nonce: string;
    eventType: 'SANDBOX_BROKER_DECISION';
    extensionId: string;
    method: string;
    resource?: string;
    granted: boolean;
    reason: string;
  };
  signature: string;
  alg: 'Ed25519';
  keyId?: string;
}

export interface BrokerDecisionSigner {
  sign(input: SignedBrokerDecision['payload']): Promise<SignedBrokerDecision>;
}

export type DecisionListener = (decision: {
  timestamp: number;
  extensionId: string;
  method: string;
  resource?: string;
  granted: boolean;
  reason: string;
  signed?: SignedBrokerDecision;
}) => void;
