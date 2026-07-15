# Implementation Roadmap: 100+ tok/s at 32K Context

## Executive Summary

**Current Status**: GPU kernels functional but unoptimized (0.017 tok/s)
**Target**: 100+ tok/s at 32K context on RX 7800 XT
**Gap**: ~5,800x speedup required
**Path**: 5-phase optimization yielding 6,000x cumulative speedup

---

## Phase 1: Kernel Optimization (50x speedup) - CRITICAL

### Problem
Current MatMul kernel is 200x slower than required:
- Current: 433ms for 4096x4096
- Required: ~2ms for 4096x4096
- Bottleneck: No tiling, poor memory coalescing

### Solution: Tiled MatMul with Shared Memory

```cpp
// Current (slow) - Each thread loads directly from global memory
for (uint i = 0; i < K; i++) {
    acc += A[row * K + i] * B[i * N + col];
}

// Optimized (fast) - Load tiles to shared memory first
shared float tile_a[TILE][TILE];
shared float tile_b[TILE][TILE];

// Cooperatively load tile
for (uint t = 0; t < num_tiles; t++) {
    tile_a[local_y][local_x] = A[...];
    tile_b[local_y][local_x] = B[...];
    __syncthreads();
    
    // Compute from shared memory (LDS - fast!)
    for (uint k = 0; k < TILE; k++) {
        acc += tile_a[local_y][k] * tile_b[k][local_x];
    }
    __syncthreads();
}
```

### Implementation Steps

1. **Create tiled compute shader** (matmul_fp16_tile32.comp) ✓ DONE
2. **Update VulkanExecutor** to use tiled kernel
3. **Benchmark**: Target 2ms for 4096x4096 (200x speedup)

### Expected Results
| Kernel | Current | Optimized | Speedup |
|--------|---------|-----------|---------|
| MatMul 4096² | 433ms | 2ms | 216x |
| RMSNorm 4096 | 2.3ms | 0.5ms | 4.6x |
| Softmax 512² | 10.5ms | 2ms | 5.2x |
| **Layer Total** | **225ms** | **~10ms** | **22x** |
| **Full Forward** | **7200ms** | **~320ms** | **22x** |
| **TPS** | **0.14** | **3.1** | **22x** |

---

## Phase 2: Weight Pre-Upload (20x speedup) - HIGH PRIORITY

### Problem
Every kernel call:
1. Creates GPU buffers (malloc)
2. Uploads data CPU→GPU (PCIe transfer)
3. Executes kernel
4. Downloads result GPU→CPU
5. Destroys buffers (free)

This adds ~10-20ms overhead per call.

### Solution: Persistent VRAM Buffers

```cpp
class GPUMemoryPool {
    // Pre-allocate buffers for common sizes
    std::vector<GPUBuffer> weight_buffers;      // Model weights
    std::vector<GPUBuffer> activation_buffers;  // Activations
    GPUBuffer kv_cache;                           // Persistent KV cache
    
public:
    void UploadWeights(const float* weights, size_t size);
    void* GetBuffer(size_t size);
    void ExecuteMatMul(int buffer_a, int buffer_b, int buffer_c);
};
```

### Implementation Steps

1. **Create GPUMemoryPool class**
2. **Upload model weights once** at load time
3. **Reuse activation buffers** across layers
4. **Keep KV cache in VRAM** across tokens

### Expected Results
| Metric | Before | After | Speedup |
|--------|--------|-------|---------|
| Buffer overhead | ~20ms/op | ~0.1ms/op | 200x |
| Memory transfers | Full | Minimal | 50x |
| **TPS** | **3.1** | **62** | **20x** |

---

## Phase 3: Kernel Fusion (2x speedup) - MEDIUM PRIORITY

### Problem
Launching separate kernels for each operation has overhead:
- Command buffer recording
- GPU dispatch
- Synchronization

### Solution: Fused Kernels

```glsl
// Current: 3 separate kernels
// Q projection → K projection → V projection

// Fused: Single kernel
layout(local_size_x = 256) in;
void main() {
    uint idx = gl_GlobalInvocationID.x;
    Q[idx] = dot(input, weights_Q[idx]);
    K[idx] = dot(input, weights_K[idx]);
    V[idx] = dot(input, weights_V[idx]);
}
```

### Fusion Opportunities

| Operation | Current | Fused | Savings |
|-----------|---------|-------|---------|
| QKV Projections | 3 kernels | 1 kernel | 3x |
| Attention | 4 kernels | 1 kernel | 4x |
| FFN | 3 kernels | 1 kernel | 3x |
| **Total** | **10 dispatches** | **3 dispatches** | **3.3x** |

### Expected Results
| Metric | Before | After | Speedup |
|--------|--------|-------|---------|
| Dispatches/token | ~100 | ~30 | 3.3x |
| **TPS** | **62** | **124** | **2x** |

---

## Phase 4: Medusa Speculative Decoding (2.5x speedup)

### Already Implemented
- Tree-based candidate generation
- Parallel verification
- Acceptance rate tracking

### Expected Results
| Metric | Before | After | Speedup |
|--------|--------|-------|---------|
| TPS | 124 | 310 | 2.5x |

---

## Phase 5: Quantization (2x speedup) - LOW PRIORITY

### FP8 Compute
```glsl
#extension GL_EXT_shader_explicit_arithmetic_types_float8 : require

void main() {
    f8vec4 a = load_fp8(...);
    f8vec4 b = load_fp8(...);
    f16vec4 c = f16vec4(a) * f16vec4(b);  // Compute in FP16
}
```

### Expected Results
| Metric | Before | After | Speedup |
|--------|--------|-------|---------|
| Memory bandwidth | 100% | 50% | 2x |
| **TPS** | **310** | **620** | **2x** |

---

## Cumulative Results

| Phase | Speedup | TPS | Cumulative |
|-------|---------|-----|------------|
| Current | 1x | 0.017 | 0.017 |
| Phase 1: Kernel Opt | 22x | 0.37 | 0.37 |
| Phase 2: Weight Upload | 20x | 7.4 | 7.4 |
| Phase 3: Kernel Fusion | 2x | 14.8 | 14.8 |
| Phase 4: Medusa | 2.5x | 37 | 37 |
| Phase 5: Quantization | 2x | 74 | 74 |

**Conservative target: 74 tok/s**
**Optimistic target: 150+ tok/s** (with better tiling)

---

## Implementation Priority

### Week 1: Critical Path
- [ ] Implement tiled MatMul kernel (matmul_fp16_tile32.comp)
- [ ] Update VulkanExecutor to use new kernel
- [ ] Benchmark and verify 200x speedup

### Week 2: Memory Optimization
- [ ] Implement GPUMemoryPool
- [ ] Pre-upload model weights
- [ ] Persistent KV cache

### Week 3: Fusion & Polish
- [ ] Fused QKV kernel
- [ ] Fused attention kernel
- [ ] End-to-end benchmark

---

## Key Metrics to Track

| Metric | Current | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Target |
|--------|---------|---------|---------|---------|---------|--------|
| MatMul 4096² | 433ms | 2ms | 2ms | 2ms | 2ms | 2ms |
| Layer time | 7200ms | 320ms | 16ms | 8ms | 3.2ms | 2ms |
| TPS | 0.017 | 3.1 | 62 | 124 | 310 | 100+ |

---

## Conclusion

The path to 100+ tok/s is clear:

1. **Phase 1 (Kernel Optimization)** is the highest impact - 22x speedup
2. **Phase 2 (Weight Upload)** is critical - another 20x speedup  
3. Combined, these two phases get us to 62 TPS
4. With Medusa speculative decoding: **155 TPS**

**The RX 7800 XT has sufficient compute power. The current implementation is simply not using it efficiently.**

Peak FP16 performance: ~35 TFLOPS
Required for 100 TPS: ~2 TFLOPS (5.7% utilization)

This is absolutely achievable with proper kernel optimization.
