# Phase 7D: Real Model Integration
## Cryptographic Verification with Real GGUF Models

**Date:** 2026-07-14  
**Status:** Implementation Complete  
**Goal:** Connect Phase 7B/7C infrastructure to real GGUF models

---

## Overview

Phase 7D bridges the gap between synthetic testing and production deployment by integrating the cryptographic verification infrastructure (hash chains, checkpoints, state resurrection) with real GGUF model loading and inference.

**The Missing Link:**
```
Real GGUF File → GGUF Loader → Checkpoint Hooks → Verified Inference → Proof Export
```

---

## Deliverables

### 1. Checkpoint Hook Headers (`src/integration/gguf_checkpoint_hooks.hpp`)
Macros for inserting verification points into the live inference pipeline:

```cpp
// In transformer layer code:
RAWRXD_CHECKPOINT_EMBEDDING(ctx, embeddings, token_count, hidden_dim);
RAWRXD_CHECKPOINT_RMSNORM(ctx, norm_output, seq_len, hidden_dim, layer_idx);
RAWRXD_CHECKPOINT_ATTENTION(ctx, attn_out, seq_len, hidden_dim, layer_idx);
RAWRXD_CHECKPOINT_KV_CACHE(ctx, k_cache, v_cache, seq_len, head_dim, layer_idx);
RAWRXD_CHECKPOINT_FFN(ctx, ffn_out, seq_len, hidden_dim, layer_idx);
RAWRXD_CHECKPOINT_LOGITS(ctx, logits, vocab_size, token_pos);
RAWRXD_CHECKPOINT_SAMPLER(ctx, token, temp, top_p, top_k, pos);
```

**Compile-time control:**
- Define `RAWRXD_ENABLE_CHECKPOINTS` to enable hashing
- Without the define, macros compile to no-ops (zero overhead)

### 2. Deterministic Comparison Script (`scripts/compare_llamacpp_rawrxd.ps1`)
PowerShell script that runs identical prompts on both llama.cpp and RawrXD, then compares:
- Generated text (character-by-character)
- Token counts
- Per-checkpoint hashes (if proof enabled)

**Usage:**
```powershell
.\scripts\compare_llamacpp_rawrxd.ps1 `
    -ModelPath "models\llama-2-7b.gguf" `
    -Prompt "The capital of France is" `
    -Tokens 10 `
    -Seed 42
```

### 3. Audit Pipeline (`scripts/audit_run_realmodel.bat`)
Automated verification pipeline that:
1. Validates model file (SHA256)
2. Extracts GGUF metadata
3. Runs inference with checkpoint capture
4. Verifies proof chain
5. Generates audit report

**Usage:**
```batch
# Quick test (10 tokens)
scripts\audit_run_realmodel.bat models\tinyllama.gguf quick

# Full test (50 tokens, multiple scenarios)
scripts\audit_run_realmodel.bat models\llama-2-7b.gguf full

# Stress test (100 tokens, edge cases)
scripts\audit_run_realmodel.bat models\llama-2-13b.gguf stress
```

---

## Integration Guide

### Step 1: Add Checkpoint Hooks to Transformer Code

Find your transformer inference loop and add checkpoints:

```cpp
// Before transformer loop
GGUFCheckpointContext checkpoint_ctx;
GGUFCheckpoint_Init(&checkpoint_ctx, 
    model_path, 
    "llama-2-7b", 
    "tiered_memory");

// In transformer layer
for (uint32_t layer = 0; layer < num_layers; layer++) {
    GGUFCheckpoint_BeginLayer(&checkpoint_ctx, layer);
    
    // RMSNorm
    rmsnorm(input, norm_output);
    RAWRXD_CHECKPOINT_RMSNORM(&checkpoint_ctx, norm_output, 
                              seq_len, hidden_dim, layer);
    
    // Attention
    attention(norm_output, q, k, v, attn_out);
    RAWRXD_CHECKPOINT_ATTENTION(&checkpoint_ctx, attn_out,
                               seq_len, hidden_dim, layer);
    
    // KV Cache
    update_kv_cache(k_cache, v_cache, k, v);
    RAWRXD_CHECKPOINT_KV_CACHE(&checkpoint_ctx, k_cache, v_cache,
                              seq_len, head_dim, layer);
    
    // FFN
    feed_forward(attn_out, ffn_out);
    RAWRXD_CHECKPOINT_FFN(&checkpoint_ctx, ffn_out,
                         seq_len, hidden_dim, layer);
    
    GGUFCheckpoint_EndLayer(&checkpoint_ctx);
}

// After logits
compute_logits(final_hidden, logits);
RAWRXD_CHECKPOINT_LOGITS(&checkpoint_ctx, logits, vocab_size, token_pos);

// After sampling
int token = sample(logits, temperature, top_p, top_k);
RAWRXD_CHECKPOINT_SAMPLER(&checkpoint_ctx, token, 
                       temperature, top_p, top_k, token_pos);

// Export proof
GGUFCheckpoint_ExportProof(&checkpoint_ctx, "inference.rawrproof");
```

### Step 2: Build with Checkpoints Enabled

```batch
# Windows (MinGW)
g++ -std=c++17 -O3 -mavx2 -mfma ^
    -DRAWRXD_ENABLE_CHECKPOINTS ^
    -I src -I src/core -I src/gguf -I src/integration ^
    src/core/hash_chain.cpp ^
    src/integration/gguf_checkpoint_hooks.cpp ^
    src/gguf/gguf_loader.cpp ^
    src/inference/transformer.cpp ^
    -o RawrXD_RealModel.exe ^
    -lkernel32

# Or use the provided build script
build_realmodel.bat
```

### Step 3: Run Comparison Test

```powershell
# Compare with llama.cpp reference
.\scripts\compare_llamacpp_rawrxd.ps1 `
    -ModelPath "models\llama-2-7b.gguf" `
    -Prompt "The quick brown fox" `
    -Tokens 20
```

Expected output:
```
========================================
RawrXD vs llama.cpp Deterministic Comparison
========================================

Step 1: Computing model SHA256...
  Model SHA256: a3b2c1d4...

Step 2: Running llama.cpp inference...
  Generated text length: 245 chars
  Approximate tokens: 20

Step 3: Running RawrXD inference with checkpoints...
  Generated text length: 245 chars
  Approximate tokens: 20

Step 4: Comparing results...
  ✓ Text output: IDENTICAL
  ✓ Token count: MATCH (20)

Step 5: Verifying RawrXD proof chain...
  ✓ Proof chain: VERIFIED

========================================
Comparison Complete
========================================
OVERALL: ✓ ALL CHECKS PASSED
```

### Step 4: Run Full Audit

```batch
# Run comprehensive audit
scripts\audit_run_realmodel.bat models\llama-2-7b.gguf full

# Check results
type audit_output\run_20260714_143052\output.txt
type audit_output\run_20260714_143052\verification.log
type audit_output\run_20260714_143052\audit_report.json
```

---

## Command Reference

### Compute Model SHA256
```batch
certutil -hashfile llama-2-13b.gguf SHA256 > llama-2-13b.sha256
```

### Run Single Deterministic Inference
```batch
.\RawrXD_RealModel.exe ^
    --model llama-2-13b.gguf ^
    --prompt "Hello" ^
    --seed 42 ^
    --enable-proofs ^
    --proof-out proof_13b_run1.rawrproof
```

### Verify Proof
```batch
.\verify_proof.exe llama-2-13b.gguf proof_13b_run1.rawrproof > verify_13b_run1.txt
```

### Full Audit Run
```batch
scripts\audit_run_realmodel.bat llama-2-13b.gguf full
```

---

## Success Criteria

| Check | Criteria | Status |
|-------|----------|--------|
| Model Loading | GGUF loads without errors | ⬜ |
| Text Generation | Output matches llama.cpp | ⬜ |
| Token Count | Same number of tokens | ⬜ |
| Proof Generation | `.rawrproof` file created | ⬜ |
| Proof Verification | `verify_proof.exe` returns 0 | ⬜ |
| Audit Report | JSON report generated | ⬜ |

---

## Next Steps

1. **Integrate checkpoint hooks** into your transformer inference code
2. **Build** `RawrXD_RealModel.exe` with checkpoint support
3. **Test** with TinyLlama first (small, fast)
4. **Compare** output with llama.cpp reference
5. **Scale up** to Llama-2-7B, 13B, 70B
6. **Production** deployment with canary rollout

---

## Troubleshooting

### "Proof file not generated"
- Ensure `RAWRXD_ENABLE_CHECKPOINTS` is defined during build
- Check that `checkpoint_mgr` is initialized before inference

### "Hash mismatch with llama.cpp"
- Verify both use same seed, temperature, top_p, top_k
- Check that llama.cpp uses `--no-mmap` for determinism
- Ensure both use CPU-only mode (disable GPU for comparison)

### "Model fails to load"
- Verify GGUF file is not corrupted: `certutil -hashfile`
- Check that model architecture is supported
- Review `metadata.txt` for GGUF version compatibility

---

## Files Created

| File | Purpose | Lines |
|------|---------|-------|
| `src/integration/gguf_checkpoint_hooks.hpp` | Checkpoint macros | 150 |
| `src/integration/gguf_checkpoint_hooks.cpp` | Implementation | 200 |
| `scripts/compare_llamacpp_rawrxd.ps1` | Comparison script | 250 |
| `scripts/audit_run_realmodel.bat` | Audit pipeline | 300 |
| `PHASE_7D_REAL_MODEL_INTEGRATION.md` | This document | 400 |

**Total:** ~1,300 lines of integration code

---

**Ready to integrate?** Start with Step 1 above, or run:
```batch
scripts\audit_run_realmodel.bat models\tinyllama.gguf quick
```
