# Auditable Validation System Specification

## Version
**Schema Version:** 1.0.0  
**Date:** 2026-07-18  
**Status:** Specification Complete, Awaiting Execution Evidence

---

## Three-State Lifecycle

Every validation stage tracks explicit state transitions:

```
IMPLEMENTED → EXECUTED → VERIFIED
     │            │           │
     ▼            ▼           ▼
  Source      Binary      Evidence
  exists      runs        meets
                          criteria
```

### State Definitions

| State | Definition | Evidence Required |
|-------|------------|-------------------|
| **IMPLEMENTED** | Source code exists and compiles | Source file SHA256 |
| **EXECUTED** | Binary ran to completion | Execution timestamp, exit code |
| **VERIFIED** | Output meets acceptance criteria | All gates pass |

### Current Status

| Stage | Implemented | Executed | Verified | Current State |
|-------|-------------|----------|----------|---------------|
| **Embedding** | ✅ | ⏳ | ⏳ | `IMPLEMENTED` |
| **RMSNorm** | ✅ | ⏳ | ⏳ | `IMPLEMENTED` |
| **QKV** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **RoPE** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **Attention** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **FFN** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **KV Cache** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **Logits** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **Sampling** | ⏳ | ⏳ | ⏳ | `PLANNED` |
| **Streaming** | ⏳ | ⏳ | ⏳ | `PLANNED` |

---

## Execution Environment Recording

### Environment Manifest

```json
{
  "schema_version": "1.0.0",
  "environment": {
    "os": {
      "name": "Windows 10 Home",
      "version": "2009",
      "build": "19045.3693",
      "architecture": "x86_64"
    },
    "cpu": {
      "vendor": "AMD",
      "model": "Ryzen 7 7800X3D",
      "cores": 8,
      "logical_processors": 16,
      "features": ["AVX2", "AVX-512", "FMA"]
    },
    "gpu": {
      "vendor": "AMD",
      "model": "Radeon RX 7800 XT",
      "vram_gb": 16,
      "driver_version": "24.5.1"
    },
    "memory": {
      "total_gb": 192,
      "available_gb": 180
    },
    "compiler": {
      "name": "MSVC",
      "version": "14.50.35717",
      "path": "C:\\VS2022Enterprise\\VC\\Tools\\MSVC\\14.50.35717\\bin\\Hostx64\\x64\\cl.exe",
      "flags": "/EHsc /O2 /W4 /nologo",
      "build_type": "Release"
    },
    "runtime": {
      "cuda_version": null,
      "vulkan_version": "1.3",
      "opencl_version": null
    }
  }
}
```

### Reproducibility Requirements

A validation run is **reproducible** if:

1. Git commit is recorded
2. Compiler version is recorded
3. Build flags are recorded
4. Input vectors are frozen (SHA256)
5. Environment is documented

---

## Evidence Schema Versioning

### Schema Evolution

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-07-18 | Initial schema with three-state lifecycle, acceptance criteria, and invariant checks |

### Schema Compatibility

- **Major version change:** Breaking changes to evidence format
- **Minor version change:** New optional fields added
- **Patch version change:** Documentation updates only

### Evidence File Header

Every evidence JSON must include:

```json
{
  "schema_version": "1.0.0",
  "evidence_format": "rawrxd-val-019",
  "generated_at": "2026-07-18T21:30:00Z",
  "generator": "embedding_stage.exe"
}
```

---

## Acceptance Criteria Recording

### Gate-Based Verification

Each stage defines explicit acceptance gates:

```json
{
  "stage": "rmsnorm",
  "acceptance_criteria": {
    "max_error": {
      "threshold": 1e-5,
      "actual": 1e-7,
      "passed": true
    },
    "shape_match": {
      "expected": [1, 10, 4096],
      "actual": [1, 10, 4096],
      "passed": true
    },
    "nan_check": {
      "max_allowed": 0,
      "actual": 0,
      "passed": true
    },
    "inf_check": {
      "max_allowed": 0,
      "actual": 0,
      "passed": true
    },
    "determinism": {
      "method": "seeded_execution",
      "seed": 42,
      "passed": true
    },
    "rms_range": {
      "min_expected": 0.1,
      "max_expected": 10.0,
      "actual_min": 0.99,
      "actual_max": 1.01,
      "passed": true
    }
  },
  "overall_passed": true
}
```

### Gate Failure Recording

If any gate fails, record explicit failure reason:

```json
{
  "stage": "rmsnorm",
  "acceptance_criteria": {
    "max_error": {
      "threshold": 1e-5,
      "actual": 2e-5,
      "passed": false,
      "failure_reason": "Numerical error exceeds tolerance"
    }
  },
  "overall_passed": false,
  "failure_analysis": "Possible causes: precision loss, incorrect epsilon value, or weight initialization mismatch"
}
```

---

## Immutable Failure Evidence

### Directory Structure

```
validation/
  evidence/
    2026-07-18/
      run-001-IMPLEMENTED/          # Initial attempt
        manifest.json
        embedding/
          evidence.json
          actual_output.bin
        rmsnorm/
          evidence.json
          actual_output.bin
        STATUS: PARTIAL
        
      run-002-EXECUTED/             # Successful execution
        manifest.json
        embedding/
          evidence.json             # PASS
          actual_output.bin
        rmsnorm/
          evidence.json             # FAIL
          actual_output.bin
          failure_analysis.txt
        STATUS: FAILED
        
      run-003-VERIFIED/             # All gates pass
        manifest.json
        embedding/
          evidence.json             # PASS
          actual_output.bin
        rmsnorm/
          evidence.json             # PASS
          actual_output.bin
        STATUS: VERIFIED
        
    latest -> symlink to most recent run
```

### Failure Preservation Rules

1. **Never overwrite evidence** - Each run gets unique directory
2. **Record failure reason** - Explicit analysis of what failed
3. **Preserve actual output** - Even failed runs save output tensors
4. **Immutable after write** - Evidence files are read-only after creation
5. **Audit trail** - Each run references previous attempts

### Status File

Each run directory contains a `STATUS` file:

```
# Run Status
RUN_ID: VAL019-2026-07-18-002
TIMESTAMP: 2026-07-18T21:30:00Z
OVERALL: FAILED

STAGES:
  embedding: PASS
  rmsnorm: FAIL

FAILURE_SUMMARY:
  rmsnorm.max_error: 2e-5 > 1e-5 (threshold exceeded)

NEXT_STEPS:
  - Debug epsilon value
  - Check weight initialization
  - Re-run with verbose logging
```

---

## Complete Evidence Example

### Successful Run (VERIFIED)

```json
{
  "schema_version": "1.0.0",
  "evidence_format": "rawrxd-val-019",
  
  "run_metadata": {
    "id": "VAL019-2026-07-18-003",
    "timestamp": "2026-07-18T21:30:00Z",
    "status": "VERIFIED",
    "previous_run": "VAL019-2026-07-18-002"
  },
  
  "environment": {
    "os": { "name": "Windows 10 Home", "version": "2009" },
    "cpu": { "vendor": "AMD", "model": "Ryzen 7 7800X3D" },
    "compiler": { "name": "MSVC", "version": "14.50.35717", "build_type": "Release" }
  },
  
  "provenance": {
    "git_commit": "8473df6ea611e082ace66b9876fb17bccebf259d",
    "source_sha256": "abc123...",
    "binary_sha256": "def456...",
    "input_vector_sha256": "sha256:4f6addc9...",
    "expected_vector_sha256": "sha256:51246bdd..."
  },
  
  "stage": "embedding",
  "kernel_version": "embedding_lookup_v1.0_native",
  
  "execution": {
    "start_time": "2026-07-18T21:30:00.000Z",
    "end_time": "2026-07-18T21:30:00.500Z",
    "duration_ms": 0.5,
    "exit_code": 0,
    "state": "VERIFIED"
  },
  
  "acceptance_criteria": {
    "max_error": { "threshold": 1e-5, "actual": 0.0, "passed": true },
    "shape_match": { "expected": [5, 4096], "actual": [5, 4096], "passed": true },
    "nan_check": { "max_allowed": 0, "actual": 0, "passed": true },
    "inf_check": { "max_allowed": 0, "actual": 0, "passed": true },
    "determinism": { "method": "seeded", "seed": 42, "passed": true }
  },
  
  "results": {
    "input_checksum": "sha256:4f6addc9659d6fb90fe94b6688a79f2a1fa8d36ec43f8f3e1d9b6528c448a384",
    "output_checksum": "sha256:51246bdd5446d14aa906f60bd996cb2e85d4e3f3f226aa1f33ee0c6a7ad9ec7b",
    "max_error": 0.0,
    "mean_error": 0.0,
    "min_error": 0.0
  },
  
  "artifacts": {
    "actual_output_path": "evidence/2026-07-18/run-003/embedding/actual_output.bin",
    "actual_output_sha256": "sha256:51246bdd..."
  },
  
  "overall_passed": true
}
```

---

## Audit Trail

### Validation System Maturity

| Area | Assessment | Evidence Location |
|------|------------|-------------------|
| Validation architecture | ✅ Mature | `AUDITABLE-VALIDATION-SYSTEM.md` |
| Evidence model | ✅ Strong | Schema 1.0.0 defined |
| Artifact validation | ✅ Demonstrated | `val-018-3/` |
| Tensor diagnostics | ⚠️ Demonstrated (with issue) | `tensor_access.cpp` |
| Kernel validation infrastructure | ✅ Implemented | `embedding_stage.cpp`, `rmsnorm_stage.cpp` |
| Numerical correctness | ⏳ Not demonstrated | Awaiting execution |
| End-to-end inference | ⏳ Planned | Future work |

### Current State Summary

**Infrastructure:** Complete and auditable  
**Execution:** Pending (binaries not built)  
**Verification:** Pending (no evidence yet collected)

**Next Milestone:** Transition Embedding stage from `IMPLEMENTED` → `EXECUTED` → `VERIFIED`
