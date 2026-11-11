# Phase 23: Q4 Dequantization Fusion

## Date
2026-07-09

## Context
Phase 22 achieved 19.62x end-to-end speedup (2.21 → 43.36 tok/s). The system is now **memory-bandwidth bound**.

### Current Bottleneck
```
Q4_0 weights (4.5 bits/weight)
      ↓
Dequantize to FP32 buffer (32 bits/weight)
      ↓
GEMM on FP32
      ↓
Discard FP32 buffer
```

**Problem**: 7x memory bandwidth waste (32/4.5 ≈ 7)

## Phase 23 Goal
Fuse dequantization with GEMM computation to eliminate the FP32 intermediate buffer:

```
Q4_0 block (32 weights + scale)
      ↓
Fused: decode + multiply-accumulate
      ↓
FP32 accumulator (no temporary buffer)
```

**Expected benefit**: 4-7x memory bandwidth reduction

## Q4_0 Format Background

### Block Structure
- **Block size**: 32 weights
- **Storage**: 32 × 4.5 bits = 144 bits = 18 bytes per block
- **Layout**: 16 bytes (scales) + 2 bytes (packed nibbles)

### Dequantization Formula
```
for i in 0..31:
    quantized = (packed_bytes[i/2] >> (4 * (i % 2))) & 0xF
    dequantized = (quantized - 8) * scale  // zero-point = 8
```

## Optimization Contract

### Level 1 — Baseline Q4 Dequantization
Measure current Q4 → FP32 → GEMM pipeline.

### Level 2 — Fused Q4 GEMM
Implement on-the-fly dequantization during GEMM:
```cpp
for each output row:
    accumulator = 0
    for each Q4_0 block:
        // Load and decompress 32 weights
        weights = decompress_q4_block(block_data)
        // Multiply-accumulate
        accumulator += dot_product(weights, input_slice)
    output[row] = accumulator
```

### Level 3 — AVX2 Q4 Decompression
Vectorize Q4 decompression:
- Load 32 bytes (2 blocks)
- Unpack nibbles to bytes
- Convert to floats
- Multiply by scale

### Level 4 — Cache-Optimized Blocking
Block access patterns to fit in L1/L2 cache:
- Process 4-8 blocks at a time
- Keep decompressed weights in registers
- Minimize memory traffic

## Validation Protocol

### Correctness Criteria
```
Fused Q4 GEMM output
        vs
Reference FP32 GEMM output

Required: max_absolute_error < 0.9999
```

### Performance Criteria
```
Memory bandwidth: Reduced by 4-7x
End-to-end TPS:  Additional 1.5-2.5x improvement
```

## Integration Plan

### Step 1: Q4 Block Loader
```cpp
struct Q4_0_Block {
    float scale;
    uint8_t nibbles[16];  // 32 weights packed as nibbles
};

void load_q4_block(const Q4_0_Block* block, float* output_32);
```

### Step 2: Fused GEMV Kernel
```cpp
void gemv_q4_fused(const Q4_0_Block* weights, const float* input,
                   float* output, int rows, int cols);
```

### Step 3: AVX2 Vectorization
```cpp
// Decompress 32 Q4 weights to 8 AVX2 registers
__m256 decompress_q4_avx2(const Q4_0_Block* block);
```

### Step 4: Integration
Replace in inference pipeline:
```cpp
// Before:
dequantize_weights(q4_weights, fp32_buffer);
gemv_avx2(fp32_buffer, input, output, rows, cols);

// After:
gemv_q4_fused(q4_weights, input, output, rows, cols);
```

## Expected Results

### Memory Bandwidth
| Operation | Before | After | Reduction |
|-----------|--------|-------|-----------|
| Weight loading | 32 bits/weight | 4.5 bits/weight | 7.1x |
| Total memory traffic | ~400 MB/s | ~60 MB/s | 6.7x |

### Performance Projection
```
Phase 22:  43.36 tok/s
Phase 23:  65-108 tok/s (projected)
Speedup:   1.5-2.5x additional
```

## Success Metrics

### Minimum Acceptable
- Correctness: max_error < 0.9999
- Memory bandwidth: Reduced by 3x

### Target
- Memory bandwidth: Reduced by 5x
- End-to-end TPS: 65-80 tok/s

### Stretch
- Memory bandwidth: Reduced by 7x
- End-to-end TPS: 100+ tok/s

## Files to Create
1. `PHASE_23_Q4_FUSION.md` (this document)
2. `kernels/q4_gemm_fused.h` / `kernels/q4_gemm_fused.cpp`
3. `tests/q4_fusion_test.cpp`
4. `PHASE_23_RESULTS.md`

## After Phase 23

### Phase 24: AVX-512 Support
- 512-bit vectors (16 floats)
- Requires compatible hardware
- Target: 2x over AVX2

### Phase 25: Kernel Fusion
- Fuse RMSNorm + Attention
- Fuse Attention + FFN
- Reduce kernel launch overhead

## Conclusion

Phase 23 attacks the memory bandwidth bottleneck that emerged after Phase 22. By fusing Q4 dequantization with GEMM, we expect:
- 4-7x memory bandwidth reduction
- 1.5-2.5x additional TPS improvement
- Sustained 65-108 tok/s throughput
