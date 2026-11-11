import type { BrokerDecision, BrokerRequestContext, CapabilityManifest } from './types';
import type { ToolchainManifest } from './toolchain-manifest';

function wildcardToRegex(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`, 'i');
}

function parsePermission(permission: string): { method: string; resourcePattern?: string } {
  const idx = permission.indexOf(':');
  if (idx < 0) {
    return { method: permission.trim() };
  }
  return {
    method: permission.slice(0, idx).trim(),
    resourcePattern: permission.slice(idx + 1).trim(),
  };
}

export class CapabilityValidator {
  public evaluate(context: BrokerRequestContext, manifest: CapabilityManifest): BrokerDecision {
    const denyRules = manifest.denied ?? [];
    if (denyRules.includes('*')) {
      if (!this.matchesAllow(context, manifest.permissions)) {
        return { granted: false, reason: 'DENY_BY_DEFAULT' };
      }
    }

    if (this.matchesRules(context, denyRules)) {
      return { granted: false, reason: 'EXPLICIT_DENY' };
    }

    if (!this.matchesAllow(context, manifest.permissions)) {
      return { granted: false, reason: 'NO_MATCHING_CAPABILITY' };
    }

    return { granted: true, reason: 'CAPABILITY_GRANTED' };
  }

  /** Evaluate a request against a toolchain manifest (schema-driven policy). */
  public evaluateToolchain(
    context: BrokerRequestContext,
    toolchain: ToolchainManifest
  ): BrokerDecision {
    const allowedIpc = toolchain.capability_allowlist.ipc ?? [];
    const allowedFs = toolchain.capability_allowlist.fs ?? [];

    // Deny network access by default if runtime_limits says so
    if (!toolchain.runtime_limits.network_access && context.method.toLowerCase().includes('network')) {
      return { granted: false, reason: 'TOOLCHAIN_NETWORK_DENIED' };
    }

    // Check IPC method allowlist
    if (allowedIpc.length > 0) {
      const methodOk = allowedIpc.includes(context.method) || allowedIpc.includes('*');
      if (!methodOk) {
        return { granted: false, reason: 'TOOLCHAIN_IPC_NOT_ALLOWED' };
      }
    }

    // Check filesystem path allowlist
    if (context.resource && allowedFs.length > 0) {
      const fsOk = allowedFs.some((rule) => {
        const [op, pattern] = rule.split(':', 2);
        if (op !== '*' && op !== context.method) return false;
        const regex = new RegExp(
          '^' + (pattern ?? '*').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$',
          'i'
        );
        return context.resource ? regex.test(context.resource) : false;
      });
      if (!fsOk) {
        return { granted: false, reason: 'TOOLCHAIN_FS_NOT_ALLOWED' };
      }
    }

    return { granted: true, reason: 'TOOLCHAIN_CAPABILITY_GRANTED' };
  }

  private matchesAllow(context: BrokerRequestContext, rules: string[]): boolean {
    return this.matchesRules(context, rules);
  }

  private matchesRules(context: BrokerRequestContext, rules: string[]): boolean {
    for (const rule of rules) {
      const parsed = parsePermission(rule);
      if (!parsed.method || parsed.method.toLowerCase() !== context.method.toLowerCase()) {
        continue;
      }

      if (!parsed.resourcePattern) {
        return true;
      }

      if (!context.resource) {
        continue;
      }

      if (wildcardToRegex(parsed.resourcePattern).test(context.resource)) {
        return true;
      }
    }

    return false;
  }
}
