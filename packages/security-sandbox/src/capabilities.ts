// Shared capability bitmask contract.
// Must match equates in spe.asm exactly.

export const Capability = {
  NONE:             0x0000000000000000n,
  READ_WORKSPACE:   0x0000000000000001n,
  WRITE_WORKSPACE:  0x0000000000000002n,
  EXECUTE_INTERNAL: 0x0000000000000004n,
  NETWORK_PROXY:    0x0000000000000008n,
  TELEMETRY_EMIT:   0x0000000000000010n,
} as const;

export type Capability = typeof Capability[keyof typeof Capability];

const PERMISSION_MAP: Record<string, Capability> = {
  read: Capability.READ_WORKSPACE,
  write: Capability.WRITE_WORKSPACE,
  execute: Capability.EXECUTE_INTERNAL,
  net: Capability.NETWORK_PROXY,
  telemetry: Capability.TELEMETRY_EMIT,
};

export function calculateCapsMask(permissions: string[]): bigint {
  let mask = Capability.NONE;
  for (const perm of permissions) {
    const cap = PERMISSION_MAP[perm.toLowerCase()];
    if (cap !== undefined) {
      mask |= cap;
    }
  }
  return mask;
}

export function hasCapability(mask: bigint, cap: Capability): boolean {
  return (mask & cap) === cap;
}
