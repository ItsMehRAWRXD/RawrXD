# Phase 22: Production Kernel Integration

## Date
2026-07-09

## Goal
Replace scalar execution paths in the actual RawrXD inference pipeline with validated AVX2 kernels and measure end-to-end TPS improvement.

## Context
Phases 17-21 validated isolated kernels with impressive speedups:
- Output Projection: 43.3x
- FFN/SWiGLU: 43.5x
- QKV Projection: 69.5x
- Attention: 1.7x

**But**: Kernel-level speedup ≠ end-to-end speedup. Phase 22 is the critical proof.

## Input
- Existing inference pipeline (`inference_pipeline.cpp`)
- Model: `phi3-mini-Q2_K.gguf` (or `Phi-3-mini-4k-instruct-q8_0.gguf`)
- Phase 15 baseline: **2.21 tok/s**

## Changes

### 1. Replace Output Projection
**Current (scalar):**
```cpp
for (int i = 0; i < vocab_size; i++) {
    float sum = 0.0f;
    for (int j = 0; j < embed_dim; j++) {
        sum += hidden[j] * output_weights[i * embed_dim + j];
    }
    logits[i] = sum;
}
```

**Replace with:**
```cpp
output_projection_avx2_mt(
    hidden,
    output_weights,
    logits,
    embed_dim,
    vocab_size,
    num_threads
);
```

### 2. Replace FFN Projections
**Current (scalar):**
```cpp
// Gate projection
for (int i = 0; i < ffn_dim; i++) {
    float sum = 0.0f;
    for (int j = 0; j < hidden_dim; j++) {
        sum += w_gate[i * hidden_dim + j] * hidden[j];
    }
    gate[i] = silu(sum);
}
// Up projection (similar)
// Down projection (similar)
```

**Replace with:**
```cpp
ffn_swiglu_avx2_mt(
    hidden,
    w_gate, w_up, w_down,
    output,
    hidden_dim,
    ffn_dim,
    num_threads
);
```

### 3. Replace QKV Projection
**Current (scalar):**
```cpp
// Q projection
for (int i = 0; i < hidden_dim; i++) {
    float sum = 0.0f;
    for (int j = 0; j < hidden_dim; j++) {
        sum += w_q[i * hidden_dim + j] * hidden[j];
    }
    q[i] = sum;
}
// K projection (similar)
// V projection (similar)
```

**Replace with:**
```cpp
qkv_projection_avx2_mt(
    hidden,
    w_qkv,
    qkv_output,
    hidden_dim,
    qkv_dim,  // 3 * hidden_dim
    num_threads
);
```

## Phase 22 Acceptance Criteria

### Correctness Gate (Before Benchmarking)
```
Scalar output logits
        vs
AVX2 output logits
```

**Required:**
```
max_absolute_error < 0.9999
```

**Validation:** Run identical prompt through both paths and compare token-by-token.

### Performance Gate
**Benchmark:** Same as Phase 15
```
Prompt:     "Hello"
Generation: 128 tokens
Model:      phi3-mini-Q2_K.gguf
Hardware:   Same as Phase 15
Compiler:   Same flags as Phase 15
```

**Record:**
```
Phase 15 baseline:    2.21 tok/s
Phase 22 measured:    [to be determined]
```

**Success Criteria:**
- ✅ Correctness: max_error < 0.9999
- ✅ Performance: Any measurable improvement (>2.21 tok/s)
- ✅ Target: 8-12 tok/s (conservative), 15-25 tok/s (optimistic)

## Integration Checklist

### Step 1: Include Kernel Headers
```cpp
#include "kernels/gemm_avx2.h"
#include "kernels/attention_avx2.h"
using namespace rawrxd::kernels;
```

### Step 2: Add Kernel Sources to Build
```cmake
# CMakeLists.txt
set(KERNEL_SOURCES
    kernels/gemm_avx2.cpp
    kernels/attention_avx2.cpp
)

target_sources(inference_pipeline PRIVATE ${KERNEL_SOURCES})
target_compile_options(inference_pipeline PRIVATE -mavx2 -mfma)
```

### Step 3: Replace Hot Paths
- [ ] Output projection call site
- [ ] FFN SwiGLU call site
- [ ] QKV projection call site
- [ ] Attention call site (if applicable)

### Step 4: Configure Threading
```cpp
const int NUM_THREADS = std::thread::hardware_concurrency();
// Or: const int NUM_THREADS = 8; // Fixed for reproducibility
```

### Step 5: Validate Correctness
- [ ] Run identical prompt through scalar and AVX2 paths
- [ ] Compare output logits
- [ ] Verify max_error < 0.9999
- [ ] Verify generated tokens match

### Step 6: Benchmark
- [ ] Run Phase 15 benchmark protocol
- [ ] Record TPS, latency, memory usage
- [ ] Compare to Phase 15 baseline

## Expected Results

### Visual Comparison

**Before (Phase 15):**
```
token step
├── output projection  ████████████████████  423.97ms (47.3%)
├── FFN               ███████████████       343.59ms (38.3%)
├── QKV               █████                 129.33ms (14.4%)
└── attention         ░                      0.03ms  (0.0%)
```

**After (Phase 22):**
```
token step
├── output projection  ▏                     ~9.79ms
├── FFN               ▏                     ~7.89ms
├── QKV               ▏                     ~1.86ms
└── attention         ▏                     ~0.21ms
```

### Performance Projection
```
Phase 15:  2.21 tok/s  (baseline)
Phase 22:  8-25 tok/s  (projected)
Speedup:   3.6-11.3x   (end-to-end)
```

## Risk Mitigation

### Risk 1: Numerical Regression
**Mitigation:** Extensive validation before benchmarking
- Compare logits token-by-token
- Verify generated text matches
- Check for NaN/Inf

### Risk 2: Thread Contention
**Mitigation:** Dynamic thread count
- Start with 4 threads if 8 shows contention
- Profile thread utilization

### Risk 3: Memory Alignment Issues
**Mitigation:** Verify alignment
- Ensure weights are 32-byte aligned
- Use `_mm256_loadu_ps` for unaligned fallback

### Risk 4: Integration Complexity
**Mitigation:** Incremental approach
- Replace one kernel at a time
- Validate after each replacement

## After Phase 22

### Phase 23: Q4 Dequantization Fusion
**Current:**
```
GGUF Q4 weight
      ↓
dequantize to FP32 buffer
      ↓
GEMM on FP32
      ↓
discard FP32 buffer
```

**Target:**
```
GGUF Q4 block (32 weights + scale)
      ↓
fused: decode + multiply-accumulate
      ↓
FP32 accumulator (no temporary buffer)
```

**Benefit:** 4x memory bandwidth reduction

## Important Note

The "45x theoretical speedup" from Phases 17-21 is **kernel-level cumulative improvement**, not end-to-end improvement. Phase 22 is the only way to validate actual end-to-end performance.

**The real milestone:** Replacing the actual inference execution path and reproducing the benchmark with the same model.

## Files to Create/Modify
1. `PHASE_22_PRODUCTION_INTEGRATION.md` (this document)
2. Modify `inference_pipeline.cpp` - Replace scalar calls
3. Modify `CMakeLists.txt` or build script - Add kernel sources
4. `PHASE_22_RESULTS.md` - Results after completion
