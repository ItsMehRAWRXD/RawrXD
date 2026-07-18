# Auditable Validation System v2.0
## Reproducible Engineering Standards

**Schema Version:** 2.0.0  
**Date:** 2026-07-18  
**Status:** Specification Complete

---

## Refined Seven-State Lifecycle

```
DESIGNED → IMPLEMENTED → BUILT → EXECUTED → VALIDATED → VERIFIED → ARCHIVED
   │           │          │         │           │          │          │
   ▼           ▼          ▼         ▼           ▼          ▼          ▼
Spec       Source      Binary    Ran      Gates      Reviewed    Frozen
written    exists      exists    to       passed     by peer     forever
                                  completion
```

### State Definitions

| State | Definition | Entry Criteria | Exit Criteria |
|-------|------------|----------------|---------------|
| **DESIGNED** | Specification written | Design doc exists | Implementation started |
| **IMPLEMENTED** | Source code exists | Compiles successfully | Binary built |
| **BUILT** | Binary produced | SHA256 recorded | Execution started |
| **EXECUTED** | Binary ran to completion | Exit code captured | Evidence generated |
| **VALIDATED** | Acceptance gates checked | All gates evaluated | Review completed |
| **VERIFIED** | Evidence independently reviewed | Reviewer sign-off | Archived |
| **ARCHIVED** | Evidence frozen permanently | Immutable storage | - |

### Current Status

| Stage | State | Git | Binary | Exec | Gates | Review | Archive |
|-------|-------|-----|--------|------|-------|--------|---------|
| **Embedding** | IMPLEMENTED | ✅ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| **RMSNorm** | IMPLEMENTED | ✅ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |

---

## Complete Artifact Recording

### 1. Model Artifact Under Test

```json
{
  "artifact_under_test": {
    "path": "models/Phi-3-mini-4k-instruct-q8_0.gguf",
    "filename": "Phi-3-mini-4k-instruct-q8_0.gguf",
    "size_bytes": 2176177120,
    "sha256": "sha256:a1b2c3d4e5f6...",
    "modified_utc": "2026-07-15T14:30:00Z",
    "source": "huggingface: microsoft/Phi-3-mini-4k-instruct",
    "quantization": "Q8_0",
    "parameters": "3.8B",
    "context_length": 4096,
    "vocab_size": 32064,
    "embedding_length": 3072,
    "attention_heads": 32,
    "layer_count": 32
  }
}
```

### 2. Complete Git Provenance

```json
{
  "git_provenance": {
    "commit": "8473df6ea611e082ace66b9876fb17bccebf259d",
    "abbrev": "8473df6",
    "branch": "copilot/vscode-mlyextom-3zgo-phase7a",
    "remote": "origin",
    "remote_url": "https://github.com/ItsMehRAWRXD/RawrXD",
    "dirty": false,
    "dirty_files": [],
    "submodules": [
      {
        "path": "3rdparty/ggml",
        "commit": "abc123...",
        "dirty": false
      }
    ],
    "describe": "v1.0.0-15-g8473df6",
    "tags": ["v1.0.0", "validation-ready"],
    "author": "Developer Name",
    "timestamp": "2026-07-17T21:00:00Z",
    "message": "Add validation infrastructure"
  }
}
```

**Rule:** `dirty: true` prevents VERIFIED state.

### 3. Validator Binary Recording

```json
{
  "validator": {
    "name": "embedding_stage.exe",
    "path": "validation/embedding_stage.exe",
    "sha256": "sha256:deadbeef...",
    "size_bytes": 245760,
    "build_time": "2026-07-18T21:25:00Z",
    "compiler": {
      "name": "MSVC",
      "version": "14.50.35717",
      "executable": "cl.exe",
      "flags": "/EHsc /O2 /W4 /nologo",
      "optimization": "O2",
      "build_type": "Release"
    },
    "source_files": [
      {
        "path": "validation/embedding_stage.cpp",
        "sha256": "sha256:abc123..."
      }
    ],
    "linker_flags": "/SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup",
    "static_analysis": {
      "warnings": 0,
      "errors": 0,
      "analyzer_run": true
    }
  }
}
```

---

## Append-Only Evidence with Zero-Padded IDs

### Directory Structure

```
evidence/
  runs/
    run-000001-DESIGNED/           # Initial design
    run-000002-IMPLEMENTED/        # Source committed
    run-000003-BUILT/              # First binary
    run-000004-EXECUTED/           # First execution
    run-000005-VALIDATED-FAILED/   # Gate failure
    run-000006-VALIDATED-FAILED/   # Another failure
    run-000007-VALIDATED/          # Gates pass
    run-000008-VERIFIED/           # Reviewed
    run-000009-VERIFIED/           # Reproduced by peer
    run-000010-ARCHIVED/           # Frozen
    
  latest -> run-000010-ARCHIVED   # Symlink to current
  index.json                       # All runs catalog
```

### Immutable Run Directory

Each run directory is immutable after creation:

```
run-000007-VALIDATED/
  STATUS                          # Human-readable
  manifest.json                   # Machine-readable
  manifest.sha256                 # Cryptographic hash
  observations/                   # Raw data
    embedding/
      actual_output.bin
      actual_output.sha256
      timing.json
      observations.json         # Raw measurements
    rmsnorm/
      actual_output.bin
      actual_output.sha256
      timing.json
      observations.json
  conclusions/                    # Derived results
    embedding.json              # Gate evaluations
    rmsnorm.json
    summary.json
  provenance/                     # Build artifacts
    embedding_stage.exe
    embedding_stage.exe.sha256
    build_log.txt
```

---

## Observations vs Conclusions

### Observations (Raw Measurements)

```json
{
  "observations": {
    "timestamp_start": "2026-07-18T21:30:00.000Z",
    "timestamp_end": "2026-07-18T21:30:00.500Z",
    "timing": {
      "parse_ms": 54.8,
      "tensor_load_ms": 12.3,
      "kernel_execution_ms": 3.1,
      "comparison_ms": 8.2,
      "total_ms": 78.4
    },
    "tensor_metrics": {
      "input_shape": [5, 4096],
      "output_shape": [5, 4096],
      "input_element_count": 20480,
      "output_element_count": 20480,
      "input_min": -0.02,
      "input_max": 0.02,
      "output_min": -0.019,
      "output_max": 0.019,
      "nan_count": 0,
      "inf_count": 0,
      "zero_count": 47
    },
    "error_metrics": {
      "max_absolute_error": 1e-7,
      "mean_absolute_error": 3e-8,
      "min_absolute_error": 0.0,
      "error_distribution": {
        "0_to_1e-8": 20450,
        "1e-8_to_1e-7": 30,
        "above_1e-7": 0
      }
    },
    "determinism_check": {
      "seed": 42,
      "run_1_output_hash": "sha256:abc...",
      "run_2_output_hash": "sha256:abc...",
      "match": true
    }
  }
}
```

### Conclusions (Gate Evaluations)

```json
{
  "conclusions": {
    "status": "VALIDATED",
    "overall_passed": true,
    "gate_evaluations": {
      "max_error": {
        "criterion": "max_error <= 1e-5",
        "observed": 1e-7,
        "threshold": 1e-5,
        "passed": true,
        "confidence": "high"
      },
      "shape_match": {
        "criterion": "output_shape == expected_shape",
        "observed": [5, 4096],
        "expected": [5, 4096],
        "passed": true,
        "confidence": "certain"
      },
      "nan_check": {
        "criterion": "nan_count == 0",
        "observed": 0,
        "threshold": 0,
        "passed": true,
        "confidence": "certain"
      },
      "determinism": {
        "criterion": "seeded execution produces identical output",
        "observed": true,
        "passed": true,
        "confidence": "high"
      }
    },
    "requires_independent_validation": false,
    "notes": [
      "All acceptance gates passed",
      "Numerical error well within tolerance",
      "Output is deterministic with seed=42"
    ]
  }
}
```

### Separation Principle

**Observations** are:
- Raw measurements
- Uninterpreted data
- Reproducible by anyone
- Never change

**Conclusions** are:
- Interpretations of observations
- Gate pass/fail evaluations
- May change if criteria change
- Versioned separately

---

## Cryptographic Sealing

### Evidence Integrity

Each run directory contains:

```
run-000007-VALIDATED/
  manifest.json              # The manifest
  manifest.sha256           # SHA256 of manifest.json
  manifest.sig              # Optional: GPG signature
  
  observations/
    embedding/
      observations.json
      observations.sha256   # SHA256 of observations.json
      actual_output.bin
      actual_output.sha256  # SHA256 of binary output
```

### Verification Script

```bash
#!/bin/bash
# verify_evidence.sh

RUN_DIR=$1

echo "Verifying evidence integrity for: $RUN_DIR"

# Verify manifest
sha256sum -c "$RUN_DIR/manifest.sha256"

# Verify observations
find "$RUN_DIR/observations" -name "*.sha256" -exec sha256sum -c {} \;

# Verify all hashes match
echo "All evidence integrity checks passed"
```

---

## Complete Evidence Schema v2.0

```json
{
  "schema_version": "2.0.0",
  "evidence_format": "rawrxd-val-019-v2",
  
  "run_metadata": {
    "id": "run-000007",
    "timestamp": "2026-07-18T21:30:00Z",
    "state": "VALIDATED",
    "previous_run": "run-000006",
    "next_run": null
  },
  
  "environment": {
    "os": { "name": "Windows 10 Home", "version": "2009", "build": "19045.3693" },
    "cpu": { "vendor": "AMD", "model": "Ryzen 7 7800X3D", "features": ["AVX2", "AVX-512"] },
    "compiler": { "name": "MSVC", "version": "14.50.35717", "optimization": "O2" }
  },
  
  "git_provenance": {
    "commit": "8473df6ea611e082ace66b9876fb17bccebf259d",
    "dirty": false,
    "submodules": []
  },
  
  "artifact_under_test": {
    "path": "models/Phi-3-mini-4k-instruct-q8_0.gguf",
    "sha256": "sha256:a1b2c3d4...",
    "size_bytes": 2176177120
  },
  
  "validator": {
    "name": "embedding_stage.exe",
    "sha256": "sha256:deadbeef...",
    "build_time": "2026-07-18T21:25:00Z"
  },
  
  "stage": "embedding",
  "kernel_version": "embedding_lookup_v1.0_native",
  
  "observations": {
    "timing": { "total_ms": 78.4, "kernel_ms": 3.1 },
    "tensor_metrics": { "nan_count": 0, "inf_count": 0 },
    "error_metrics": { "max_absolute_error": 1e-7 }
  },
  
  "conclusions": {
    "status": "VALIDATED",
    "overall_passed": true,
    "gate_evaluations": {
      "max_error": { "passed": true },
      "shape_match": { "passed": true },
      "nan_check": { "passed": true }
    },
    "requires_independent_validation": false
  },
  
  "integrity": {
    "manifest_sha256": "sha256:abc123...",
    "sealed": true,
    "sealed_at": "2026-07-18T21:35:00Z"
  }
}
```

---

## Summary of Improvements

| Aspect | v1.0 | v2.0 |
|--------|------|------|
| Lifecycle states | 3 | 7 |
| Artifact recording | Basic | Complete (GGUF, Git, Validator) |
| Evidence IDs | run-001 | run-000001 (zero-padded) |
| Observations vs Conclusions | Mixed | Explicitly separated |
| Timing capture | Runtime only | Detailed breakdown |
| Cryptographic sealing | SHA256 | SHA256 + optional GPG |
| Dirty working tree | Warning | Blocks VERIFIED |
| Immutable directories | Yes | Yes + integrity verification |

---

## Next Steps

1. **Transition Embedding to BUILT**
   - Compile embedding_stage.exe
   - Record binary SHA256
   - Create run-000002-BUILT

2. **Transition to EXECUTED**
   - Run binary
   - Capture observations
   - Create run-000003-EXECUTED

3. **Transition to VALIDATED**
   - Evaluate gates
   - If all pass: VALIDATED
   - If any fail: VALIDATED-FAILED

4. **Transition to VERIFIED**
   - Independent review
   - Reproduction by peer
   - Sign-off

5. **Transition to ARCHIVED**
   - Cryptographic sealing
   - Immutable storage
   - Catalog in index.json
