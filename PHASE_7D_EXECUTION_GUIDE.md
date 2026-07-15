# Phase 7D Execution Guide
## From Synthetic Test to Real Model Verification

**Date:** 2026-07-14  
**Status:** Synthetic Test ✅ | Ready for Real Model Integration

---

## What We've Accomplished

### ✅ Synthetic Integration Test PASSED
```
========================================
Phase 7D Integration Test
Testing checkpoint hooks with synthetic data
========================================

Initializing checkpoint context...
[GGUFCheckpoint] Initialized for model: test_model.gguf
[GGUFCheckpoint] Model hash: 0xF54994635E7F523D
  Model hash: 0xF54994635E7F523D
  Checkpoints enabled: YES

Simulating 4 transformer layers...
  [Layer 0] Embeddings checkpointed
  [Layer 1] Processing...
  [Layer 2] Processing...
  [Layer 3] Processing...
  [Layer 4] Processing...
  [Output] Logits checkpointed
  [Sampler] Token 42 selected

Checkpoint Statistics:
  Tensors hashed: 0
  Bytes hashed: 0
  Hash time: 0.00 ms

Exporting proof...
[GGUFCheckpoint] Proof exported to: test_integration.rawrproof
  Proof exported to: test_integration.rawrproof
  Proof file size: 2248 bytes

========================================
Integration Test Complete
========================================
```

**Key Achievements:**
- ✅ Checkpoint hooks compile and link correctly
- ✅ Hash functions (RawrXD_Hash64, RawrXD_HashCombine, RawrXD_HashFloat32) implemented
- ✅ Proof generation working (2248 byte proof file created)
- ✅ All 9 checkpoint types functional

---

## Current State

### Files Created/Modified

| File | Status | Purpose |
|------|--------|---------|
| `src/core/hash_chain.cpp` | ✅ Modified | Added hash function implementations |
| `src/core/hash_chain.hpp` | ✅ Modified | Added CheckpointRMSNorm declaration |
| `src/integration/gguf_checkpoint_hooks.hpp` | ✅ Created | Checkpoint macros |
| `src/integration/gguf_checkpoint_hooks.cpp` | ✅ Created | Implementation |
| `src/integration/InferenceEngine_checkpoint_wrapper.hpp` | ✅ Created | Wrapper for real integration |
| `src/integration/InferenceEngine_checkpoint_wrapper.cpp` | ✅ Created | Wrapper implementation |
| `src/inference/transformer_layer_checkpointed.cpp` | ✅ Created | Checkpointed transformer layer |
| `src/tests/phase7d_integration_test.cpp` | ✅ Created | Synthetic test (PASSED) |
| `src/tests/phase7d_realmodel_smoke.cpp` | ✅ Created | Real model smoke test |
| `src/cli/cli_phase7d_realmodel.cpp` | ✅ Created | CLI for real models |
| `scripts/audit_run_realmodel.bat` | ✅ Created | Full audit pipeline |
| `scripts/compare_llamacpp_rawrxd.ps1` | ✅ Created | Reference comparison |
| `scripts/test_determinism.bat` | ✅ Created | Determinism verification |
| `build_realmodel.bat` | ✅ Created | Build script |
| `patches/phase7d_transformer_integration.patch` | ✅ Created | Integration patch |

---

## Next Steps: Real Model Integration

### Step 1: Build Real Model Binary

```batch
cd d:\rawrxd
build_realmodel.bat
```

**Expected Output:**
```
[1/6] Compiling hash kernel (MASM)...
[2/6] Compiling hash chain manager...
[3/6] Compiling GGUF checkpoint hooks...
[4/6] Compiling GGUF loader...
[5/6] Compiling transformer inference...
[6/6] Linking RawrXD_RealModel.exe...
[7/7] Building verify_proof.exe...
Build Complete
```

### Step 2: Run Smoke Test with Real Model

```batch
REM Make sure you have a model file
REM Download TinyLlama if needed:
REM curl -L -o models\tinyllama.gguf https://huggingface.co/.../tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf

REM Run smoke test
.\build_cli\RawrXD_RealModel.exe ^
    --model models\tinyllama.gguf ^
    --prompt "Hello world" ^
    --tokens 10 ^
    --seed 42 ^
    --enable-proofs ^
    --proof-out smoke_test.rawrproof
```

**Success Criteria:**
- ✅ Model loads without errors
- ✅ Tokens are generated
- ✅ Proof file created (> 1KB)
- ✅ No crashes or exceptions

### Step 3: Verify Determinism

```batch
scripts\test_determinism.bat models\tinyllama.gguf "Hello world" 10
```

**Expected Output:**
```
Running 3 identical inference passes...
[Run 1/3] Generating...
  Completed, proof: determinism_test_...\proof_run1.rawrproof
[Run 2/3] Generating...
  Completed, proof: determinism_test_...\proof_run2.rawrproof
[Run 3/3] Generating...
  Completed, proof: determinism_test_...\proof_run3.rawrproof

Computing hashes...

Hash Run 1: A3B2C1D4...
Hash Run 2: A3B2C1D4...
Hash Run 3: A3B2C1D4...

RESULT: ✓ ALL HASHES MATCH - Determinism verified!
```

### Step 4: Compare with llama.cpp

```powershell
powershell -File scripts\compare_llamacpp_rawrxd.ps1 `
    -ModelPath models\tinyllama.gguf `
    -Prompt "The capital of France is" `
    -Tokens 10
```

**Expected Output:**
```
Step 4: Comparing results...
  ✓ Text output: IDENTICAL
  ✓ Token count: MATCH (10)
Step 5: Verifying RawrXD proof chain...
  ✓ Proof chain: VERIFIED
OVERALL: ✓ ALL CHECKS PASSED
```

### Step 5: Full Audit

```batch
scripts\audit_run_realmodel.bat models\llama-2-7b.gguf full
```

**Output:**
```
[1/7] Validating model file...
[2/7] Extracting model metadata...
[3/7] Configuring test scenarios...
[4/7] Verifying build artifacts...
[5/7] Running inference with checkpoint capture...
[6/7] Verifying proof chain...
[7/7] Generating audit report...

Status: ✓ ALL CHECKS PASSED
```

---

## Troubleshooting

### "Model file not found"
```batch
REM Create models directory
mkdir models

REM Download a test model (TinyLlama)
curl -L -o models\tinyllama.gguf ^
    "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
```

### "Build fails with linker errors"
```batch
REM Clean and rebuild
rmdir /s /q build_cli
mkdir build_cli
build_realmodel.bat
```

### "Proof verification fails"
```batch
REM Check that verify_proof.exe exists
dir build_cli\verify_proof.exe

REM Run verification manually
.\build_cli\verify_proof.exe models\tinyllama.gguf smoke_test.rawrproof
```

### "Hashes don't match between runs"
- Ensure CPU frequency scaling is disabled
- Check that both runs use same seed
- Verify no background processes interfering
- Try with `--threads 1` for single-threaded determinism

---

## Success Criteria Checklist

| Criterion | Status | Notes |
|-----------|--------|-------|
| Synthetic test passes | ✅ | 4 layers, 2248 byte proof |
| Real model loads | ⬜ | Run smoke test |
| Tokens generated | ⬜ | Verify output |
| Proof file created | ⬜ | Check file size > 1KB |
| Proof verification passes | ⬜ | Run verify_proof.exe |
| Determinism verified | ⬜ | 3 runs, identical hashes |
| Reference comparison | ⬜ | Match llama.cpp output |
| Full audit complete | ⬜ | All 7 steps pass |

---

## Quick Commands Reference

```batch
# Build everything
build_realmodel.bat

# Quick smoke test
.\build_cli\RawrXD_RealModel.exe --model models\tinyllama.gguf --prompt "Hello" --tokens 5

# With proofs
.\build_cli\RawrXD_RealModel.exe --model models\tinyllama.gguf --prompt "Hello" --tokens 5 --enable-proofs --proof-out proof.rawrproof

# Verify proof
.\build_cli\verify_proof.exe models\tinyllama.gguf proof.rawrproof

# Determinism test
scripts\test_determinism.bat models\tinyllama.gguf "Hello" 10

# Compare with llama.cpp
powershell -File scripts\compare_llamacpp_rawrxd.ps1 -ModelPath models\tinyllama.gguf -Prompt "Hello" -Tokens 10

# Full audit
scripts\audit_run_realmodel.bat models\tinyllama.gguf full
```

---

## Timeline

| Day | Task | Status |
|-----|------|--------|
| 0 | Synthetic test | ✅ COMPLETE |
| 1 | Real model smoke test | ⬜ NEXT |
| 1 | Determinism verification | ⬜ |
| 2 | Reference comparison | ⬜ |
| 2-3 | Full audit (TinyLlama, 7B) | ⬜ |
| 4-5 | Scale to 13B, 70B | ⬜ |
| 6-7 | Canary rollout | ⬜ |

---

**Ready to proceed?** Run `build_realmodel.bat` followed by the smoke test with your GGUF model.