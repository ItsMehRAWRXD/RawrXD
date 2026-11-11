import { calculateCapsMask } from './capabilities';
import type { CapabilityManifest } from './types';

// Minimal ref-struct-napi compatible layout for RestrictedManifest
// In production, use ffi-napi + ref-struct-napi for full marshaling.
interface RestrictedManifest {
  PathPtr: Buffer;
  CapsMask: bigint;
}

function buildManifestStruct(path: string, mask: bigint): RestrictedManifest {
  return {
    PathPtr: Buffer.from(path + '\0', 'utf8'),
    CapsMask: mask,
  };
}

export interface SpawnResult {
  processHandle: number;
  capsMask: bigint;
}

export class ExtensionBroker {
  private readonly spePath: string;

  constructor(speDllPath: string) {
    this.spePath = speDllPath;
  }

  public async spawnExtension(manifest: CapabilityManifest): Promise<SpawnResult> {
    const mask = calculateCapsMask(manifest.permissions);

    // Validate: deny if mask contains unknown high bits
    if (mask > 0xFFFFFFFFn) {
      throw new Error('Sovereign Enforcer: Spawn Rejected by Kernel Gate — invalid capability mask');
    }

    const struct = buildManifestStruct(manifest.extensionId, mask);

    // In production: call SPE via ffi-napi:
    // const spe = ffi.Library(this.spePath, {
    //   SpawnRestricted: ['uint64', ['pointer']]
    // });
    // const handle = spe.SpawnRestricted(struct.PathPtr);

    // MVP: simulate SPE validation
    const simulatedHandle = this.simulateSpeCall(struct);
    if (simulatedHandle === 0) {
      return { processHandle: 0, capsMask: mask };
    }
    if (simulatedHandle === 1) {
      throw new Error('Sovereign Enforcer: Spawn Rejected — invalid manifest');
    }
    if (simulatedHandle === 2) {
      throw new Error('Sovereign Enforcer: Spawn Rejected by Kernel Gate');
    }
    throw new Error(`Sovereign Enforcer: Unknown SPE return code ${simulatedHandle}`);
  }

  private simulateSpeCall(struct: RestrictedManifest): number {
    // Simulate SPE validation logic:
    // 1) PathPtr must be non-null
    if (!struct.PathPtr || struct.PathPtr.length === 0) {
      return 1;
    }
    // 2) CapsMask upper 32 bits must be zero
    if (struct.CapsMask > 0xFFFFFFFFn) {
      return 2;
    }
    return 0;
  }
}
