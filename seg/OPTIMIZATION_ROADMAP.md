# RawrXD Sovereign Inference - Optimization Roadmap

## Current Status (Baseline)

**Model**: unlock-1B-Q4_K_M.gguf  
**Hardware**: AVX2, 16 threads, no AVX-512  
**Performance**: 14-17 tokens/sec  
**Latency**: 58-70 ms/token  
**Bottleneck**: Compute-bound (transformer layers)

---

## Optimization Priority Matrix

| Priority | Optimization | Expected Gain | Complexity | Status |
|----------|--------------|---------------|------------|--------|
| **P0** | Fused attention kernels | +20-30% | Medium | ⏳ Ready |
| **P0** | Quantized matmul (Q4_K_M) | +15-25% | Medium | ⏳ Ready |
| **P1** | AVX-512 kernels | +50-100% | High | ⏳ Hardware-dependent |
| **P1** | Speculative decoding (C8) | +2-3x | High | ✅ Implemented |
| **P2** | KV-cache optimization | +5-10% | Low | ⏳ Memory-bound only |
| **P2** | Multi-threading (batch) | +10x batch | Medium | ⏳ Prompt processing |
| **P3** | FlashAttention V2 | +2x memory | High | ⏳ Long sequences |

---

## Phase 1: Kernel Fusion (Immediate)

**Goal**: Reduce memory round-trips

```cpp
// Current: 3 separate passes
RMSNorm(x) → Attention(x) → RMSNorm(x) → MLP(x)

// Fused: 1 pass with intermediate buffers
FusedTransformerLayer(x, weights) → y
```

**Expected**: 14 → 18 tok/s (+28%)

---

## Phase 2: Quantized Compute (Week 1)

**Goal**: Use Q4_K_M weights directly in matmul

```cpp
// Current: Dequantize → F32 matmul
Q4_K_M → F32 → matmul

// Optimized: Quantized matmul
Q4_K_M × F32 → F32 (on-the-fly dequantize)
```

**Expected**: 18 → 23 tok/s (+28%)

---

## Phase 3: AVX-512 (Hardware upgrade)

**Goal**: Leverage 512-bit vectors

```cpp
// AVX2: 8 floats per operation
__m256 a = _mm256_load_ps(ptr);  // 256-bit

// AVX-512: 16 floats per operation  
__m512 a = _mm512_load_ps(ptr);  // 512-bit
```

**Expected**: 23 → 35-45 tok/s (+50-100%)

---

## Phase 4: Speculative Decoding (C8)

**Goal**: Generate multiple tokens per forward pass

```cpp
// Current: 1 token per forward
for (i = 0; i < N; i++) {
    token = Forward(model, tokens);  // Full 24 layers
}

// Speculative: Draft 4 tokens, verify in parallel
draft = DraftModel(tokens);        // Cheap 6-layer model
verify = TargetModel(tokens+draft); // Verify all 4
accept = Verify(draft, verify);    // Usually 2-3 accepted
```

**Expected**: 45 → 90-135 tok/s (2-3x)

---

## Phase 5: Memory Optimization (When bound)

**Goal**: Reduce KV cache bandwidth

```cpp
// Current: F32 KV cache
KV cache = 2 × seq_len × num_heads × head_dim × 4 bytes

// Optimized: Q8_0 KV cache  
KV cache = 2 × seq_len × num_kv_heads × head_dim × 1 byte
// + GQA: num_kv_heads = num_heads / 4
```

**Expected**: When memory-bound, +20-40% throughput

---

## Benchmark Infrastructure

All optimizations validated via:

```bash
# Baseline
run_benchmark.exe --model model.gguf --tokens 128 --iterations 5

# Results in results.json:
{
  "tokens_per_sec": 17.33,
  "avg_latency_ms": 57.72,
  "transformer_time_ms": 7387.71
}
```

---

## Summary

**Current**: 14-17 tok/s  
**Phase 1+2**: 23 tok/s (+35%)  
**Phase 3+4**: 90-135 tok/s (5-8x)  
**Target**: 100+ tok/s for real-time chat

**Next Action**: Implement fused attention kernels (P0)
