import { CapabilityValidator } from './capability-validator';
import type {
  BrokerDecision,
  BrokerDecisionSigner,
  BrokerRequestContext,
  CapabilityManifest,
  DecisionListener,
} from './types';
import { ProcessBroker } from './process-broker';
import { ToolchainRegistry } from './toolchain-registry';
import type { ToolchainManifest } from './toolchain-manifest';

function makeNonce(): string {
  const now = Date.now();
  return `${now}-${Math.random().toString(36).slice(2, 10)}`;
}

export class SandboxManager {
  private readonly manifests = new Map<string, CapabilityManifest>();
  private readonly processBroker = new ProcessBroker();
  private readonly validator = new CapabilityValidator();
  private readonly listeners = new Set<DecisionListener>();
  private readonly signer?: BrokerDecisionSigner;
  private readonly toolchainRegistry = new ToolchainRegistry();

  constructor(options: { signer?: BrokerDecisionSigner } = {}) {
    this.signer = options.signer;
  }

  public registerManifest(manifest: CapabilityManifest): void {
    this.manifests.set(manifest.extensionId, manifest);
  }

  public getProcessBroker(): ProcessBroker {
    return this.processBroker;
  }

  public getToolchainRegistry(): ToolchainRegistry {
    return this.toolchainRegistry;
  }

  public onDecision(listener: DecisionListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  public async authorize(context: BrokerRequestContext): Promise<BrokerDecision> {
    const manifest = this.manifests.get(context.extensionId);
    if (!manifest) {
      const denied: BrokerDecision = { granted: false, reason: 'MANIFEST_NOT_REGISTERED' };
      await this.emitDecision(context, denied);
      return denied;
    }

    const decision = this.validator.evaluate(context, manifest);
    await this.emitDecision(context, decision);
    return decision;
  }

  /** Authorize using a toolchain manifest (schema-driven policy). */
  public async authorizeToolchain(
    context: BrokerRequestContext,
    toolchainIdentity: string
  ): Promise<BrokerDecision> {
    const toolchain = this.toolchainRegistry.resolve(toolchainIdentity);
    if (!toolchain) {
      const denied: BrokerDecision = { granted: false, reason: 'TOOLCHAIN_NOT_REGISTERED' };
      await this.emitDecision(context, denied);
      return denied;
    }

    const decision = this.validator.evaluateToolchain(context, toolchain);
    await this.emitDecision(context, decision);
    return decision;
  }

  private async emitDecision(context: BrokerRequestContext, decision: BrokerDecision): Promise<void> {
    const timestamp = Date.now();
    let signed;

    if (this.signer) {
      try {
        signed = await this.signer.sign({
          timestamp,
          nonce: makeNonce(),
          eventType: 'SANDBOX_BROKER_DECISION',
          extensionId: context.extensionId,
          method: context.method,
          resource: context.resource,
          granted: decision.granted,
          reason: decision.reason,
        });
      } catch {
        signed = undefined;
      }
    }

    const event = {
      timestamp,
      extensionId: context.extensionId,
      method: context.method,
      resource: context.resource,
      granted: decision.granted,
      reason: decision.reason,
      signed,
    };

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Keep auditing non-blocking.
      }
    }
  }
}
