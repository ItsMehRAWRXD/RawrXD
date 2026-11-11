# RawrXD Governance

## Overview

This directory contains governance policies and operational tooling for RawrXD enterprise deployments. These phases ensure the runtime is not just built correctly, but operated predictably and verifiably.

---

## Governance Phases

| Phase | Component | Purpose | Status |
|-------|-----------|---------|--------|
| **L.5** | `SUPPORT_POLICY.md` | Long-Term Support (LTS) policy | ✅ Complete |
| **L.6** | `security_patch_validation.ps1` | Security patch validation gates | ✅ Complete |
| **L.7** | `reproducible_build.ps1` | Reproducible build system | ✅ Complete |
| **L.8** | `deployment_profiles.ps1` | Enterprise deployment profiles | ✅ Complete |

---

## Phase L.6: Security Patch Validation

**File:** `phase_l6_security_patch_validation/security_patch_validation.ps1`

**Purpose:** Every security patch must pass 6 validation gates before release:

1. **Unit Tests** — Core functionality verification
2. **Benchmark Regression** — Performance delta < 2%
3. **Hotpatch Integrity** — Rollback capability, memory boundaries
4. **Memory Safety** — ASan, MSan, UBSan validation
5. **Chaos Recovery** — Fault injection and recovery
6. **Audit Verification** — Chain of custody validation

**Usage:**
```powershell
.\security_patch_validation.ps1 `
    -PatchPath ".\patches\CVE-2026-XXXX.patch" `
    -BaselineVersion "1.0.0" `
    -OutputPath ".\validation_reports"
```

**Output:**
- `security_patch_validation_{timestamp}.json` — Full report
- `security_patch_summary_{timestamp}.txt` — Human-readable summary
- Exit code 0 = approved for release

---

## Phase L.7: Reproducible Builds

**File:** `phase_l7_reproducible_builds/reproducible_build.ps1`

**Purpose:** Create deterministic, verifiable, signed releases:

- Source commit pinning
- Compiler version locking (MSVC 14.50.35717)
- Build flags documentation
- SPDX SBOM generation
- Binary checksums (SHA256)
- Code signing (optional)

**Usage:**
```powershell
.\reproducible_build.ps1 `
    -Version "1.0.0" `
    -SourceCommit "abc123" `
    -OutputPath ".\releases" `
    -SignRelease
```

**Output:**
- `source_manifest.json` — Source file hashes
- `compiler_manifest.json` — Toolchain info
- `sbom.spdx.json` — SPDX 2.3 SBOM
- `checksums.sha256` — Binary hashes
- `build_report.json` — Complete build report
- `signature.json` — Code signing info (if enabled)

---

## Phase L.8: Deployment Profiles

**File:** `phase_l8_deployment_profiles/deployment_profiles.ps1`

**Purpose:** Define and validate deployment configurations for different use cases:

### Developer Profile
- Single node, local models
- Community support
- Permissive security
- No monitoring required

### Production Profile
- 1-4 nodes, LTS runtime
- Monitoring and audit
- RBAC and TLS required
- 99.9% SLA

### Enterprise Sovereign Profile
- 3-100 nodes, federation
- Zero trust, mTLS
- SOC2/ISO27001 compliance
- 99.95% SLA, dedicated support

**Usage:**
```powershell
# Generate configuration
.\deployment_profiles.ps1 -Profile enterprise -OutputPath ".\config"

# Validate existing configuration
.\deployment_profiles.ps1 -Profile enterprise -ValidateOnly
```

**Output:**
- `rawrxd.config.json` — Main configuration
- `docker-compose.yml` — Container orchestration
- `kubernetes/` — K8s manifests (enterprise)
- `.env` — Environment variables
- `validate-environment.ps1` — Pre-flight checks
- `DEPLOYMENT_GUIDE.md` — Deployment instructions

---

## Quick Start

```powershell
# 1. Validate a security patch
cd phase_l6_security_patch_validation
.\security_patch_validation.ps1 -PatchPath "..\..\patches\security.patch" -BaselineVersion "1.0.0"

# 2. Create reproducible build
cd ..\phase_l7_reproducible_builds
.\reproducible_build.ps1 -Version "1.0.1" -SourceCommit "def456" -SignRelease

# 3. Configure deployment
cd ..\phase_l8_deployment_profiles
.\deployment_profiles.ps1 -Profile production -OutputPath "..\..\deploy"

# 4. Validate environment
cd ..\..\deploy
.\validate-environment.ps1
```

---

## Integration with LTS Policy

These governance phases operationalize the LTS policy:

| LTS Requirement | Governance Phase |
|-----------------|------------------|
| Security patches in 72 hours | L.6 — Validation gates |
| Reproducible builds | L.7 — Build system |
| Deployment profiles | L.8 — Configuration |
| Compliance (SOC2/ISO27001) | L.8 — Enterprise profile |

---

## Security Advisory Workflow

```
Discovery
    |
Triage
    |
Severity Assignment (CVSS)
    |
Patch Development
    |
Regression Benchmark (L.6)
    |
Security Patch Validation (L.6)
    |
Reproducible Build (L.7)
    |
Security Advisory Published
    |
Release
```

---

## Success Criteria

✅ **L.6** — Security patches validated in 6 gates  
✅ **L.7** — Reproducible builds with SBOM and checksums  
✅ **L.8** — Three deployment profiles (dev/prod/enterprise)  

---

## Next Steps

The governance framework is complete. RawrXD now has:

- LTS policy (L.5)
- Security validation (L.6)
- Reproducible builds (L.7)
- Deployment profiles (L.8)

This completes the transition from **building the platform** to **operating the platform**.
