// Toolchain Manifest — schema-driven identity and capability policy for external tools.
// Each manifest defines a bounded execution contract for a specific tool identity.

export interface ToolchainManifest {
  /** Human-readable tool name (e.g., "msvc-compiler") */
  tool: string;
  /** Unique identity string (e.g., "com.microsoft.msvc.v143") */
  identity: string;
  /** Absolute or relative path to the executable */
  executable: string;
  /** Runtime resource constraints */
  runtime_limits: RuntimeLimits;
  /** Capability allowlist per domain */
  capability_allowlist: CapabilityAllowlist;
  /** Optional: version of the manifest schema */
  manifest_version?: string;
  /** Optional: expected SHA-256 hash of the executable for integrity verification */
  expected_hash?: string;
}

export interface RuntimeLimits {
  /** Whether the tool may open network sockets */
  network_access: boolean;
  /** Maximum memory in megabytes */
  max_memory_mb: number;
  /** Maximum CPU percentage (0-100) */
  max_cpu_percent: number;
  /** Maximum execution time in seconds (0 = unlimited) */
  max_execution_seconds?: number;
  /** Whether the tool may spawn child processes */
  allow_child_processes?: boolean;
}

export interface CapabilityAllowlist {
  /** Filesystem operations: method:path_pattern */
  fs?: string[];
  /** IPC methods allowed via JSON-RPC */
  ipc?: string[];
  /** Environment variable keys the tool may read */
  env?: string[];
  /** Registry keys the tool may read (Windows) */
  registry?: string[];
}

export interface ToolchainValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateToolchainManifest(manifest: unknown): ToolchainValidationResult {
  const errors: string[] = [];

  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, errors: ['Manifest must be an object'] };
  }

  const m = manifest as Record<string, unknown>;

  if (typeof m.tool !== 'string' || m.tool.length === 0) {
    errors.push('Missing or invalid "tool" field');
  }
  if (typeof m.identity !== 'string' || m.identity.length === 0) {
    errors.push('Missing or invalid "identity" field');
  }
  if (typeof m.executable !== 'string' || m.executable.length === 0) {
    errors.push('Missing or invalid "executable" field');
  }

  if (!m.runtime_limits || typeof m.runtime_limits !== 'object') {
    errors.push('Missing or invalid "runtime_limits" field');
  } else {
    const rl = m.runtime_limits as Record<string, unknown>;
    if (typeof rl.network_access !== 'boolean') {
      errors.push('runtime_limits.network_access must be a boolean');
    }
    if (typeof rl.max_memory_mb !== 'number' || rl.max_memory_mb <= 0) {
      errors.push('runtime_limits.max_memory_mb must be a positive number');
    }
    if (typeof rl.max_cpu_percent !== 'number' || rl.max_cpu_percent < 0 || rl.max_cpu_percent > 100) {
      errors.push('runtime_limits.max_cpu_percent must be between 0 and 100');
    }
  }

  if (!m.capability_allowlist || typeof m.capability_allowlist !== 'object') {
    errors.push('Missing or invalid "capability_allowlist" field');
  } else {
    const ca = m.capability_allowlist as Record<string, unknown>;
    for (const key of ['fs', 'ipc', 'env', 'registry']) {
      if (ca[key] !== undefined && !Array.isArray(ca[key])) {
        errors.push(`capability_allowlist.${key} must be an array of strings`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
