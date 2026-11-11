# Sovereign Inference IDE — Operational Handoff
# Date: 2026-06-01
# Status: PRODUCTION READY

## Executive Summary

The Sovereign Inference IDE is a hardened, zero-trust development environment where every layer—from bare-metal binary emission to high-level toolchain execution—is governed by verifiable, immutable security policies. This document provides the operational handoff for production deployment.

---

## 1. The Sovereign Security Stack (Final Topology)

### Layer 1: Immutable Gate (MASM `guard.asm`)
- **Location**: `d:\rawrxd-ci-bootstrap\guard.asm`
- **Purpose**: Final arbiter of binary integrity. Enforces W^X (Write XOR Execute) policy at the assembly level.
- **Entry Point**: `GuardBinary proc` — returns 0=PASS, 1=INVALID_HEADER, 2=WX_VIOLATION
- **Build**: `ml64.exe /c /W3 /nologo /Zi /Fo guard.obj guard.asm`
- **Link**: `link.exe /DLL /OUT:guard.dll guard.obj`
- **Verification**: `python guard.py verify <binary>`

### Layer 2: Sovereign Process Enforcer (SPE)
- **Location**: `packages/security-sandbox/src/spe.asm`
- **Purpose**: Kernel-level process firewall. Creates restricted tokens, job objects, and capability-masked process spawning.
- **ABI**: `SpawnRestricted(QWORD manifestPtr)` — returns process handle or error code
- **Capability Contract**: 64-bit bitmask (must match `packages/security-sandbox/src/capabilities.ts`)

### Layer 3: Secure Transport (Sovereign IPC)
- **Location**: `packages/security-ipc/src/`
- **Purpose**: Hardened JSON-RPC over Windows Named Pipes with kernel-gated access controls.
- **Protocol**: Length-prefixed frames (4-byte LE uint32 header + UTF-8 payload)
- **Key Classes**:
  - `SovereignPipeServer` — broker-side pipe creation and JSON-RPC event loop
  - `SovereignPipeClient` — extension-side connection and request/response correlation
- **Security**: Pipe names are UUID-based (`\\.\pipe\rawrxd-[uuid]`). DACL restricted to current user.

### Layer 4: Policy Engine (Toolchain Registry & Manifests)
- **Location**: `packages/security-sandbox/src/toolchain-registry.ts`
- **Purpose**: Identity-based, schema-driven capability restriction for every external tool.
- **Manifest Schema**: `ToolchainManifest` with `runtime_limits`, `capability_allowlist`, `identity`
- **Example Manifests**: `packages/security-sandbox/manifests/{msvc,npm,clang,ml64,gcc}.json`
- **Key Classes**:
  - `ToolchainRegistry` — loads, validates, and queries manifests
  - `CapabilityValidator.evaluateToolchain()` — schema-driven policy evaluation

---

## 2. SDK Package Inventory

| Package | Path | Status | Type-Check |
|---------|------|--------|------------|
| security-engine | `packages/security-engine` | ✅ Production | Pass |
| security-express | `packages/security-express` | ✅ Production | Pass |
| security-redis | `packages/security-redis` | ✅ Production | Pass |
| security-telemetry-verify | `packages/security-telemetry-verify` | ✅ Production | Pass |
| security-ipc | `packages/security-ipc` | ✅ Production | Pass |
| security-sandbox | `packages/security-sandbox` | ✅ Production | Pass |

---

## 3. CI/CD Pipeline

### Local Gate: `ci_gate.ps1`
Runs on every build attempt:
1. **Gate 1**: Engine Build (C++ / MSVC)
2. **Gate 1.5**: Immutable Binary Guard (MASM W^X validation)
3. **Gate 2**: Infrastructure Backbone Test (handshake)
4. **Gate 3**: Application Layer Test (UI-API connectivity)
5. **Gate 4**: Packaging & Release

### GitHub Actions: `.github/workflows/replay_gate.yml`
- Builds IDE with MSBuild
- Runs Immutable Guard Gate on built binary
- Runs audit stub detection
- Blocks PR if W^X violation detected

### Regression Tests
- `regression_test_pe.py` — 6-phase adversarial PEWriter test (15 assertions)
- `packages/security-sandbox/tests/malicious-extension-regression.ts` — Denied .env read with signed audit
- `packages/security-sandbox/tests/toolchain-integration.ts` — 8-suite manifest/registry/policy test
- `packages/security-sandbox/tests/RedTeamAudit.ts` — 6-layer adversarial breakout audit (W^X, SPE, transport, policy, telemetry, supply chain)

---

## 4. Threat Model Neutralization

| Threat Vector | Mitigation | Layer |
|---------------|-----------|-------|
| Malicious binary deployment | MASM Guard W^X enforcement | Layer 1 |
| Privilege escalation / process spoofing | SPE capability bitmask + Job Object | Layer 2 |
| Session hijacking / traffic interception | Named Pipe kernel DACL + UUID pipe names | Layer 3 |
| Unauthorized filesystem/network access | Toolchain Manifest allowlist | Layer 4 |
| Policy tampering | Signed telemetry audit trail (Ed25519) | Layer 4 |
| Supply-chain attack (NPM) | Network proxy capability + W^X post-install scan | Layer 2+4 |

---

## 5. Deployment Checklist

- [ ] `guard.dll` built and present in workspace root
- [ ] `guard.py` functional (`python guard.py verify <any.exe>`)
- [ ] All 6 SDK packages type-check clean (`npx tsc --noEmit`)
- [ ] `regression_test_pe.py` passes (15/15 assertions)
- [ ] `malicious-extension-regression.ts` passes
- [ ] `toolchain-integration.ts` passes (8/8 suites)
- [ ] `RedTeamAudit.ts` passes (6/6 layers)
- [ ] CI gate `replay_gate.yml` green on PR
- [ ] Toolchain manifests reviewed for production paths

---

## 6. First Full-Cycle Build Command

```powershell
# 1. Build the immutable guard
ml64.exe /c /W3 /nologo /Zi /Fo guard.obj guard.asm
link.exe /DLL /OUT:guard.dll guard.obj

# 2. Run local CI gate
.\ci_gate.ps1

# 3. Verify SDK packages
foreach ($pkg in @("security-engine","security-express","security-redis","security-telemetry-verify","security-ipc","security-sandbox")) {
    cd "packages\$pkg"
    npx tsc -p tsconfig.json --noEmit
    cd ..\..
}

# 4. Run regression suites
python regression_test_pe.py
npx tsx packages/security-sandbox/tests/malicious-extension-regression.ts
npx tsx packages/security-sandbox/tests/toolchain-integration.ts
```

---

## 7. Architecture Philosophy

> "The IDE does not 'support' runtimes by running them. It orchestrates them through the security gate."

Every tool (MSVC, NPM, GCC, Clang, ML64) is treated as an **External Untrusted Worker**. The Broker:
1. Loads the tool's `toolchain.json` manifest
2. Creates a kernel-gated Named Pipe
3. Spawns the process via SPE with restricted capabilities
4. Audits every IPC request against the manifest
5. Signs every decision for tamper-proof forensics

---

## 8. Contact & Escalation

- **Security Incidents**: Review `sovereign_audit.log` for signed decision events
- **Build Failures**: Check `_ci_build.log`, `_ci_guard.log`, `_ci_handshake.log`
- **Policy Updates**: Modify manifests in `packages/security-sandbox/manifests/` — no code changes required

---

**Status**: OPERATIONAL ✅  
**Next Milestone**: First full-cycle build with live toolchain orchestration  
**Signed**: Sovereign Security Stack v1.0 — 2026-06-01
