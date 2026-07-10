# Phase 3: Kernel Fusion Implementation Plan

## Overview
Fuse multiple GPU operations into single kernels to reduce launch overhead and improve memory locality.

## Target Operations to Fuse

### 1. Fused QKV Projection (Priority 1)
**Current**: 3 separate MatMul kernels (Q, K, V)
**Fused**: 1 kernel computing all three
**Expected Speedup**: 2.5x
**Memory**: Load input once, compute all three projections

### 2. Fused Attention (Priority 1)
**Current**: Q×K^T → Softmax → ×V (3 kernels)
**Fused**: Flash Attention-style single kernel
**Expected Speedup**: 2.5x
**Memory**: O(1) instead of O(N²) for attention scores

### 3. Fused FFN (Priority 2)
**Current**: Gate → Up → Down (3 kernels)
**Fused**: Single kernel with SiLU activation
**Expected Speedup**: 2x

## Implementation Steps

### Step 1: Create Fused Shaders
- [x] `fused_qkv_projection.comp` - QKV in one kernel
- [x] `fused_attention.comp` - Flash Attention style
- [ ] `fused_ffn.comp` - Feed-forward network

### Step 2: Compile to SPIR-V
```bash
glslangValidator -V --target-env vulkan1.2 fused_qkv_projection.comp -o fused_qkv_projection.spv
glslangValidator -V --target-env vulkan1.2 fused_attention.comp -o fused_attention.spv
```

### Step 3: Update Executor
- Add fused kernel loading in `LoadShaders()`
- Create `ExecuteFusedQKV()` method
- Create `ExecuteFusedAttention()` method
- Add feature flag `use_fused_kernels`

### Step 4: Benchmark
- Compare separate vs fused kernels
- Measure memory bandwidth reduction
- Verify correctness

## Expected Performance

| Component | Current | Fused | Speedup |
|-----------|---------|-------|---------|
| QKV Projection | 3 kernels | 1 kernel | 2.5x |
| Attention | 3 kernels | 1 kernel | 2.5x |
| FFN | 3 kernels | 1 kernel | 2x |
| **Total** | **9 kernels** | **3 kernels** | **2.5x** |

## Cumulative Performance

| Phase | Speedup | TPS |
|-------|---------|-----|
| Baseline | 1x | 0.14 |
| Phase 2 (Weight Cache) | 7x | 1.0 |
| Phase 3 (Kernel Fusion) | 2.5x | 2.5 |
| Phase 4 (Medusa) | 2.5x | 6.25 |
| Phase 5 (Quantization) | 3x | 18.75 |

**After Phase 3**: ~2.5 tok/s (still below 100 target, but getting closer)

## Risk Mitigation

### Risk: Fused kernels are slower
**Mitigation**: Keep separate kernels as fallback
```cpp
if (config.use_fused_kernels && fused_available) {
    ExecuteFusedQKV(...);
} else {
    ExecuteQKVSeparate(...);
}
```

### Risk: Memory pressure
**Mitigation**: Flash Attention uses O(1) memory

### Risk: Numerical precision
**Mitigation**: Test against reference implementation

## Next Actions

1. Compile fused shaders to SPIR-V
2. Update executor with fused methods
3. Add feature flag integration
4. Benchmark and validate
5. Ship if 2x+ speedup achieved
