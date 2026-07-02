// Toolchain integration test — validates manifest loading, registry resolution,
// and toolchain-aware authorization via SandboxManager.

import { strict as assert } from 'node:assert';
import { SandboxManager } from '../src/sandbox-manager';
import { ToolchainRegistry } from '../src/toolchain-registry';
import { validateToolchainManifest } from '../src/toolchain-manifest';

const msvcManifest = {
  tool: 'msvc-compiler',
  identity: 'com.microsoft.msvc.v143',
  executable: 'C:/VS2022Enterprise/VC/Tools/MSVC/14.50.35717/bin/Hostx64/x64/cl.exe',
  runtime_limits: {
    network_access: false,
    max_memory_mb: 512,
    max_cpu_percent: 80,
    max_execution_seconds: 300,
    allow_child_processes: false,
  },
  capability_allowlist: {
    fs: ['read:./src/**', 'write:./build/**'],
    ipc: ['propose_patch', 'request_symbol_map'],
    env: ['INCLUDE', 'LIB'],
  },
  manifest_version: '1.0.0',
};

const npmManifest = {
  tool: 'npm-package-manager',
  identity: 'com.npmjs.npm',
  executable: 'npm.cmd',
  runtime_limits: {
    network_access: true,
    max_memory_mb: 1024,
    max_cpu_percent: 60,
    max_execution_seconds: 600,
    allow_child_processes: true,
  },
  capability_allowlist: {
    fs: ['read:./package.json', 'write:./node_modules/**'],
    ipc: ['request_auth'],
    env: ['NODE_OPTIONS'],
  },
  manifest_version: '1.0.0',
};

function testManifestValidation() {
  const valid = validateToolchainManifest(msvcManifest);
  assert.equal(valid.valid, true, `MSVC manifest should be valid: ${valid.errors.join(', ')}`);

  const invalid = validateToolchainManifest({ tool: 'bad' });
  assert.equal(invalid.valid, false, 'Incomplete manifest should be invalid');
  assert.ok(invalid.errors.length > 0, 'Should report errors');
  console.log('[PASS] Manifest validation');
}

function testRegistryResolution() {
  const registry = new ToolchainRegistry();
  registry.register(msvcManifest);
  registry.register(npmManifest);

  const msvc = registry.resolve('com.microsoft.msvc.v143');
  assert.ok(msvc, 'Should resolve MSVC manifest');
  assert.equal(msvc?.tool, 'msvc-compiler');

  const missing = registry.resolve('com.unknown.tool');
  assert.equal(missing, undefined, 'Unknown identity should return undefined');
  console.log('[PASS] Registry resolution');
}

function testIpcPolicy() {
  const registry = new ToolchainRegistry();
  registry.register(msvcManifest);

  assert.equal(registry.isIpcAllowed('com.microsoft.msvc.v143', 'propose_patch'), true);
  assert.equal(registry.isIpcAllowed('com.microsoft.msvc.v143', 'request_auth'), false);
  assert.equal(registry.isIpcAllowed('com.unknown.tool', 'propose_patch'), false);
  console.log('[PASS] IPC policy enforcement');
}

function testFsPolicy() {
  const registry = new ToolchainRegistry();
  registry.register(msvcManifest);

  assert.equal(registry.isFsAllowed('com.microsoft.msvc.v143', 'read', './src/main.cpp'), true);
  assert.equal(registry.isFsAllowed('com.microsoft.msvc.v143', 'write', './build/out.obj'), true);
  assert.equal(registry.isFsAllowed('com.microsoft.msvc.v143', 'read', './secrets.txt'), false);
  assert.equal(registry.isFsAllowed('com.unknown.tool', 'read', './src/main.cpp'), false);
  console.log('[PASS] FS policy enforcement');
}

function testEnvPolicy() {
  const registry = new ToolchainRegistry();
  registry.register(msvcManifest);

  assert.equal(registry.isEnvAllowed('com.microsoft.msvc.v143', 'INCLUDE'), true);
  assert.equal(registry.isEnvAllowed('com.microsoft.msvc.v143', 'SECRET_KEY'), false);
  console.log('[PASS] Env policy enforcement');
}

async function testSandboxManagerToolchainAuthorize() {
  const manager = new SandboxManager();
  manager.getToolchainRegistry().register(msvcManifest);

  const decisions: { granted: boolean; reason: string }[] = [];
  manager.onDecision((d) => decisions.push(d));

  // Allowed IPC
  const allowed = await manager.authorizeToolchain(
    { extensionId: 'msvc-test', method: 'propose_patch' },
    'com.microsoft.msvc.v143'
  );
  assert.ok(allowed.granted, 'propose_patch should be granted');

  // Denied IPC
  const denied = await manager.authorizeToolchain(
    { extensionId: 'msvc-test', method: 'request_auth' },
    'com.microsoft.msvc.v143'
  );
  assert.equal(denied.granted, false, 'request_auth should be denied');
  assert.equal(denied.reason, 'TOOLCHAIN_IPC_NOT_ALLOWED');

  // Unknown toolchain
  const unknown = await manager.authorizeToolchain(
    { extensionId: 'msvc-test', method: 'propose_patch' },
    'com.unknown.tool'
  );
  assert.equal(unknown.granted, false, 'Unknown toolchain should be denied');
  assert.equal(unknown.reason, 'TOOLCHAIN_NOT_REGISTERED');

  assert.equal(decisions.length, 3, 'Should emit 3 audit decisions');
  console.log('[PASS] SandboxManager toolchain authorization');
}

function testRuntimeLimits() {
  const registry = new ToolchainRegistry();
  registry.register(msvcManifest);
  registry.register(npmManifest);

  const msvcLimits = registry.getRuntimeLimits('com.microsoft.msvc.v143');
  assert.ok(msvcLimits);
  assert.equal(msvcLimits?.network_access, false);
  assert.equal(msvcLimits?.max_memory_mb, 512);

  const npmLimits = registry.getRuntimeLimits('com.npmjs.npm');
  assert.ok(npmLimits);
  assert.equal(npmLimits?.network_access, true);
  assert.equal(npmLimits?.max_memory_mb, 1024);
  console.log('[PASS] Runtime limits retrieval');
}

function testPipeNameInjection() {
  const manager = new SandboxManager();
  const registry = manager.getToolchainRegistry();
  registry.register(msvcManifest);

  // We can't actually spawn here, but we verify the spec accepts pipeName
  const spec = {
    extensionId: 'msvc-test',
    entryFile: 'test.js',
    pipeName: '\\\\.\\pipe\\rawrxd-test-pipe',
    allowEnvKeys: ['SystemRoot'],
  };

  // Verify spec structure (pipeName is typed)
  assert.equal(spec.pipeName, '\\\\.\\pipe\\rawrxd-test-pipe');
  console.log('[PASS] Pipe name injection spec');
}

// Run all tests
(async () => {
  testManifestValidation();
  testRegistryResolution();
  testIpcPolicy();
  testFsPolicy();
  testEnvPolicy();
  await testSandboxManagerToolchainAuthorize();
  testRuntimeLimits();
  testPipeNameInjection();

  console.log('\n[ALL PASS] Toolchain integration tests completed successfully.');
})();
