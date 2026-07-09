# Phase 15 — Autoregressive Throughput Validation

## Status
**COMPLETE** ✅

## Purpose
Establish reproducible steady-state generation metrics before any optimization work.

---

## Model Configuration

| Parameter | Value |
|-----------|-------|
| Model | phi3-mini-4k-instruct-q8_0.gguf |
| Architecture | phi3 |
| Parameters | 3.8B |
| Quantization | Q4_0 |
| Context Length | 131,072 |
| Embedding Dim | 3,072 |
| Hidden Dim | 8,192 |
| Layers | 32 |
| Heads | 32 |
| Vocab Size | 32,064 |

---

## System Configuration

| Parameter | Value |
|-----------|-------|
| Platform | Windows x64 |
| Compiler | g++ (MinGW) |
| Optimization | -O2 |
| Threading | Single-threaded |
| KV Cache | **Disabled** |
| SIMD | **Disabled** (scalar kernels) |
| GPU | **Disabled** |
| Memory | System RAM |

---

## Test Parameters

| Parameter | Value |
|-----------|-------|
| Prompt | "Hello" |
| Prompt Tokens | 3 (BOS + "Hello" + EOS) |
| Generation Target | 128 tokens |
| Measurement | Steady-state decode |

---

## Results

### Prefill Phase

| Metric | Value |
|--------|-------|
| Tokens | 3 |
| Time | 1,401.97 ms |
| **Throughput** | **2.14 tok/s** |

### Decode Phase (Sustained Generation)

| Metric | Value |
|--------|-------|
| Tokens | 128 |
| Time | 57,913 ms |
| **Throughput** | **2.21 tok/s** |
| Steady-State Throughput | 2.21 tok/s |

### Latency Distribution

| Percentile | Latency |
|------------|---------|
| Mean | 452.43 ms/token |
| P50 | ~452 ms/token |
| P95 | ~520 ms/token |
| **P99** | **558.88 ms/token** |
| Max | ~560 ms/token |

---

## Key Observations

### Prefill ≈ Decode
```
Prefill:  2.14 tok/s
Decode:    2.21 tok/s
```

**Interpretation**: The dominant cost is per-token forward pass, not prompt ingestion overhead. This indicates the bottleneck is in the transformer computation itself, not the initial setup.

### Latency Stability
- P99/Mean ratio: 1.23 (23% tail latency variation)
- Acceptable for baseline; suggests consistent per-token cost

---

## Optimization State

| Feature | Status | Notes |
|---------|--------|-------|
| KV Cache | ❌ Disabled | Recomputes full attention each token |
| SIMD | ❌ Disabled | Scalar floating-point operations |
| Multi-threading | ❌ Disabled | Single-threaded GEMM |
| GPU | ❌ Disabled | CPU-only execution |
| Quantization | ✅ Q4_0 | Weights quantized, dequantized per access |
| Attention | ⚠️ Simplified | No multi-head split |

---

## Files

| File | Purpose |
|------|---------|
| `benchmark_autoregressive.cpp` | Main benchmark harness |
| `benchmark_autoregressive.exe` | Compiled benchmark |

---

## Reproduction Steps

```bash
cd d:\rawrxd\tests
g++ -std=c++17 -O2 benchmark_autoregressive.cpp -o benchmark_autoregressive.exe
.\benchmark_autoregressive.exe "Hello" 128
```

---

## Next Phase

**Phase 16 — Component-Level Profiling**

Goal: Identify where the 452ms per token is spent:
- Token embedding
- RMSNorm
- QKV projection
- RoPE
- Attention
- FFN/SwiGLU
- Output projection
- Sampling

---

## Baseline Frozen

**Date**: 2026-07-09
**Commit**: Phase 15 completion
**Status**: Baseline established, ready for profiling

---

## Measurement Loop Established

```
Change
  ↓
Benchmark (against this baseline)
  ↓
Compare
  ↓
Accept / Reject
```

This baseline is the reference point for all future optimization work.
