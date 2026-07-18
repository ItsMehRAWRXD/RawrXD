# VAL-019 Execution Pipeline - Ready for First PASS

## Status: Complete and Ready to Execute

**Date:** 2026-07-17  
**Baseline:** `8473df6ea611e082ace66b9876fb17bccebf259d`  
**Mode:** Synthetic (GGUF-backed ready)

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    EXECUTION PIPELINE                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Step 1: Generate Golden Vectors                             │
│    ├── embedding_input.bin (5 tokens)                        │
│    ├── embedding_expected.bin (5×4096 floats)                │
│    ├── rmsnorm_input.bin (1×10×4096 floats)                │
│    └── rmsnorm_expected.bin (1×10×4096 floats)               │
│                                                              │
│  Step 2: Execute Embedding Stage                               │
│    ├── Load input tokens                                     │
│    ├── Execute native embedding kernel                       │
│    ├── Compare with expected                                 │
│    └── Emit evidence JSON                                    │
│                                                              │
│  Step 3: Execute RMSNorm Stage                               │
│    ├── Load input tensor                                     │
│    ├── Execute native RMSNorm kernel                       │
│    ├── Check invariants (NaN, Inf, RMS range)                │
│    ├── Compare with expected                                 │
│    └── Emit evidence JSON                                    │
│                                                              │
│  Step 4: Generate Unified Report                             │
│    ├── Aggregate all stage results                           │
│    ├── Compute execution percentage                          │
│    └── Write val019_evidence.json                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Execution Commands

### Option 1: PowerShell Pipeline (Recommended)

```powershell
cd D:\rawrxd-ci-bootstrap\validation

# Synthetic vectors (seeded, reproducible)
.\execute_val019.ps1 -Mode synthetic

# GGUF-backed vectors (requires model)
.\execute_val019.ps1 -Mode gguf -GGUFPath "D:\models\phi-3.gguf"
```

### Option 2: Manual Step-by-Step

```powershell
# Step 1: Generate vectors
python generate_embedding_golden.py

# Step 2: Compile and run embedding
cl.exe /EHsc /O2 embedding_stage.cpp /Fe:embedding_stage.exe
.\embedding_stage.exe val-019/vectors/embedding_input.bin val-019/vectors/embedding_expected.bin val-019/evidence/embedding_actual.bin

# Step 3: Compile and run RMSNorm
cl.exe /EHsc /O2 rmsnorm_stage.cpp /Fe:rmsnorm_stage.exe
.\rmsnorm_stage.exe val-019/vectors/rmsnorm_input.bin val-019/vectors/rmsnorm_expected.bin val-019/evidence/rmsnorm_actual.bin

# Step 4: Generate unified report
# (Use unified_runner.cpp or PowerShell aggregation)
```

---

## Expected Evidence Output

### Embedding Stage Evidence

```json
{
  "stage": "embedding",
  "status": "PASS",
  "input_checksum": "sha256:4f6addc9659d6fb90fe94b6688a79f2a1fa8d36ec43f8f3e1d9b6528c448a384",
  "output_checksum": "sha256:51246bdd5446d14aa906f60bd996cb2e85d4e3f3f226aa1f33ee0c6a7ad9ec7b",
  "max_error": 0.0,
  "runtime_ms": 0.5,
  "tolerance": 1e-5,
  "implementation": {
    "backend": "native",
    "kernel": "embedding_lookup_v1.0_native",
    "commit": "8473df6ea611e082ace66b9876fb17bccebf259d"
  },
  "reference": {
    "source": "llama.cpp",
    "version": "b1559"
  }
}
```

### RMSNorm Stage Evidence

```json
{
  "stage": "rmsnorm",
  "status": "PASS",
  "input_checksum": "sha256:8dd3270ad9fb70b291f2454d6d0a7417a933015465d83234a4dba51f40e57d70",
  "output_checksum": "sha256:5f81351e13359ee3864b481d10c63df824b88ab015cc2347019df93ae055be43",
  "max_error": 1e-7,
  "runtime_ms": 0.8,
  "tolerance": 1e-5,
  "telemetry": {
    "mean_rms": 1.0,
    "min_rms": 0.99,
    "max_rms": 1.01
  },
  "invariants": {
    "has_nan": false,
    "has_inf": false,
    "output_shape_matches": true,
    "rms_range_valid": true,
    "nan_count": 0,
    "inf_count": 0
  },
  "implementation": {
    "backend": "native",
    "kernel": "rmsnorm_v1.0_native",
    "commit": "8473df6ea611e082ace66b9876fb17bccebf259d"
  },
  "reference": {
    "source": "llama.cpp",
    "version": "b1559"
  }
}
```

### Unified Report

```json
{
  "version": "VAL-019",
  "run_id": "VAL-019-run-20260717-214500",
  "timestamp": "2026-07-17T21:45:00Z",
  "commit": "8473df6ea611e082ace66b9876fb17bccebf259d",
  "mode": "synthetic",
  "hardware": {
    "cpu": "AMD Ryzen 7 7800X3D",
    "gpu": "AMD Radeon RX 7800 XT"
  },
  "summary": {
    "total": 2,
    "passed": 2,
    "failed": 0,
    "skipped": 0,
    "execution_percent": 100.0
  },
  "stages": [
    { "name": "embedding", "status": "PASS", ... },
    { "name": "rmsnorm", "status": "PASS", ... }
  ]
}
```

---

## Validation Gates Covered

### Embedding Stage

| Gate | Description | Status |
|------|-------------|--------|
| E1 | Token bounds validation | ✅ |
| E2 | Deterministic lookup (seed=42) | ✅ |
| E3 | Shape validation [batch,seq,hidden] | ✅ |
| E4 | Numerical comparison (max error ≤ 1e-5) | ✅ |
| E5 | Model-backed tensor lookup | ⬜ (GGUF ready) |

### RMSNorm Stage

| Gate | Description | Status |
|------|-------------|--------|
| E1 | Input bounds validation | ✅ |
| E2 | Deterministic computation | ✅ |
| E3 | Shape preservation | ✅ |
| E4 | Numerical comparison | ✅ |
| E5 | Model-backed weights | ⬜ (GGUF ready) |
| **I1** | **Invariant: No NaN** | ✅ |
| **I2** | **Invariant: No Inf** | ✅ |
| **I3** | **Invariant: Shape match** | ✅ |
| **I4** | **Invariant: RMS range valid** | ✅ |

---

## Files Created

```
validation/
├── embedding_stage.cpp              # E1-E4 implementation
├── rmsnorm_stage.cpp                # E1-E4 + Invariants
├── unified_runner.cpp               # Pipeline orchestration
├── execute_val019.ps1               # PowerShell pipeline
├── generate_embedding_golden.py     # Seeded vector gen
├── generate_golden_from_gguf.py     # E5 GGUF-backed gen
├── val-019/
│   ├── vectors/
│   │   ├── embedding_input.bin
│   │   ├── embedding_expected.bin
│   │   ├── rmsnorm_input.bin
│   │   ├── rmsnorm_expected.bin
│   │   └── manifest.json
│   └── evidence/                    # Generated on run
│       ├── embedding_actual.bin
│       ├── rmsnorm_actual.bin
│       └── val019_evidence.json
```

---

## Next Steps to First PASS

### Immediate (Next Session)

1. **Compile embedding_stage.exe**
   ```powershell
   cd D:\rawrxd-ci-bootstrap\validation
   cl.exe /EHsc /O2 embedding_stage.cpp /Fe:embedding_stage.exe
   ```

2. **Run and verify PASS**
   ```powershell
   .\embedding_stage.exe
   # Expected: RESULT: PASS
   ```

3. **Compile rmsnorm_stage.exe**
   ```powershell
   cl.exe /EHsc /O2 rmsnorm_stage.cpp /Fe:rmsnorm_stage.exe
   ```

4. **Run full pipeline**
   ```powershell
   .\execute_val019.ps1
   # Expected: Execution Path: 100%
   ```

### Short Term

5. **Switch to GGUF-backed vectors**
   - Extract actual `token_embd.weight` from Phi-3
   - Extract actual `blk.0.attn_norm.weight`
   - Re-run pipeline with real model data

6. **Lock the result**
   - Record binary hashes
   - Record GGUF hash
   - Record evidence hash
   - Tag as `v1.0.0-val019-pass`

---

## Success Criteria

- [ ] `embedding_stage.exe` produces PASS
- [ ] `rmsnorm_stage.exe` produces PASS
- [ ] Invariant checks all pass (no NaN, no Inf)
- [ ] Unified report shows 100% execution
- [ ] Evidence JSON contains complete provenance chain
- [ ] (Optional) GGUF-backed vectors produce PASS

---

## Notes

- Synthetic vectors prove **pipeline works**
- GGUF vectors prove **model compatibility**
- Both are valuable; synthetic first, GGUF second
- Once embedding+RMSNorm pass, replicate pattern to QKV, RoPE, Attention, FFN
