// ToolchainRegistry — loads and queries toolchain manifests for identity-based policy.

import {
  type ToolchainManifest,
  type ToolchainValidationResult,
  validateToolchainManifest,
} from './toolchain-manifest';

export class ToolchainRegistry {
  private readonly manifests = new Map<string, ToolchainManifest>();

  /** Register a single manifest after validation. */
  public register(manifest: ToolchainManifest): ToolchainValidationResult {
    const result = validateToolchainManifest(manifest);
    if (!result.valid) {
      return result;
    }
    this.manifests.set(manifest.identity, manifest);
    return { valid: true, errors: [] };
  }

  /** Load and register a manifest from a JSON string. */
  public loadFromJson(json: string): ToolchainValidationResult {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      return { valid: false, errors: ['Invalid JSON'] };
    }
    if (!parsed || typeof parsed !== 'object') {
      return { valid: false, errors: ['Manifest must be an object'] };
    }
    return this.register(parsed as ToolchainManifest);
  }

  /** Look up a manifest by identity. */
  public resolve(identity: string): ToolchainManifest | undefined {
    return this.manifests.get(identity);
  }

  /** Check if a specific IPC method is allowed for a given identity. */
  public isIpcAllowed(identity: string, method: string): boolean {
    const manifest = this.manifests.get(identity);
    if (!manifest) return false;
    const allowed = manifest.capability_allowlist.ipc ?? [];
    return allowed.includes(method) || allowed.includes('*');
  }

  /** Check if a filesystem operation is allowed for a given identity. */
  public isFsAllowed(identity: string, operation: string, path: string): boolean {
    const manifest = this.manifests.get(identity);
    if (!manifest) return false;
    const allowed = manifest.capability_allowlist.fs ?? [];
    for (const rule of allowed) {
      const [op, pattern] = rule.split(':', 2);
      if (op === '*' || op === operation) {
        if (this.matchPattern(path, pattern ?? '*')) {
          return true;
        }
      }
    }
    return false;
  }

  /** Check if an environment variable may be read. */
  public isEnvAllowed(identity: string, key: string): boolean {
    const manifest = this.manifests.get(identity);
    if (!manifest) return false;
    const allowed = manifest.capability_allowlist.env ?? [];
    return allowed.includes(key) || allowed.includes('*');
  }

  /** Return all registered identities. */
  public listIdentities(): string[] {
    return Array.from(this.manifests.keys());
  }

  /** Return runtime limits for an identity. */
  public getRuntimeLimits(identity: string): ToolchainManifest['runtime_limits'] | undefined {
    return this.manifests.get(identity)?.runtime_limits;
  }

  private matchPattern(path: string, pattern: string): boolean {
    const regex = new RegExp(
      '^' +
        pattern
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*/g, '.*')
          .replace(/\?/g, '.') +
        '$',
      'i'
    );
    return regex.test(path);
  }
}
