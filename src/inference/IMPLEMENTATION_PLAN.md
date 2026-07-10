# Implementation Plan: Tiled MatMul Kernel

## Overview
This is the highest-impact optimization (15x speedup) needed to reach 100+ tok/s.

## Current State
- MatMul 4096x4096: **433ms** (way too slow)
- Target: **<30ms** (15x faster)
- RX 7800 XT peak: 35 TFLOPS FP16
- Current utilization: <0.001%

## The Problem

### Current Implementation Issues
1. **No tiling**: Each thread computes one element, poor cache utilization
2. **No shared memory**: Global memory accessed repeatedly
3. **Scalar loads**: Loading one float at a time
4. **Small workgroups**: 256 threads, not utilizing all CUs

### Why It's Slow
```
Current: 4096x4096x4096 = 137 GFLOP / 433ms = 0.3 GFLOPS
Peak:    35,000 GFLOPS
Utilization: 0.001%
```

## The Solution: Tiled MatMul

### Algorithm
```
For each 32x32 output tile:
    Load 32x32 tile from A into shared memory
    Load 32x32 tile from B into shared memory
    Synchronize threads
    Compute partial dot products
    Synchronize threads
    Move to next K tile
Write output tile
```

### Benefits
1. **Shared memory**: O(n) memory accesses instead of O(n³)
2. **Coalesced access**: Threads load consecutive memory
3. **Vectorized loads**: Load 4-8 floats at once
4. **Better occupancy**: More workgroups running concurrently

## Implementation Steps

### Step 1: Create Optimized Shader (30 min)
File: `shaders/matmul_fp16_tile32.comp`
- 32x32 thread blocks
- Shared memory tiles
- Vectorized loads (vec4)
- RDNA3 optimizations

### Step 2: Update Executor (30 min)
File: `vulkan_executor_impl.cpp`
- Add new pipeline creation
- Update dispatch to use 2D workgroups
- Handle tile boundaries

### Step 3: Benchmark (15 min)
File: `benchmark_matmul_tiled.cpp`
- Compare old vs new
- Verify correctness
- Profile with GPU counters

### Step 4: Integrate (15 min)
- Replace old MatMul in transformer
- Run full benchmark
- Validate TPS improvement

## Expected Results

### MatMul Performance
| Size | Current | Optimized | Speedup |
|------|---------|-----------|---------|
| 512x512 | 50ms | 3ms | 17x |
| 1024x1024 | 100ms | 8ms | 12x |
| 2048x2048 | 200ms | 20ms | 10x |
| 4096x4096 | 433ms | 30ms | 14x |

### Transformer Layer
| Component | Current | Optimized | Speedup |
|-----------|---------|-----------|---------|
| MatMul (x4) | 142ms | 10ms | 14x |
| Layer total | 225ms | 93ms | 2.4x |
| Full model | 7207ms | 2976ms | 2.4x |

### Throughput
| Metric | Current | Optimized | Target |
|--------|---------|-----------|--------|
| Base TPS | 0.14 | 0.34 | 100+ |
| With Medusa | 0.35 | 0.85 | 100+ |

## Code Structure

### Shader: matmul_fp16_tile32.comp
```glsl
#version 450
#extension GL_EXT_shader_explicit_arithmetic_types_float16 : require

layout(local_size_x = 32, local_size_y = 32) in;

layout(set = 0, binding = 0) readonly buffer A { float16_t data[]; } a;
layout(set = 0, binding = 1) readonly buffer B { float16_t data[]; } b;
layout(set = 0, binding = 2) writeonly buffer C { float16_t data[]; } c;

layout(push_constant) uniform Params {
    uint M, N, K;
} params;

shared float16_t tile_a[32][32];
shared float16_t tile_b[32][32];

void main() {
    uint local_x = gl_LocalInvocationID.x;
    uint local_y = gl_LocalInvocationID.y;
    uint group_x = gl_WorkGroupID.x;
    uint group_y = gl_WorkGroupID.y;
    
    uint row = group_y * 32 + local_y;
    uint col = group_x * 32 + local_x;
    
    if (row >= params.M || col >= params.N) return;
    
    float16_t acc = float16_t(0.0);
    
    for (uint tile_k = 0; tile_k < params.K; tile_k += 32) {
        // Load tiles into shared memory
        if (tile_k + local_x < params.K)
            tile_a[local_y][local_x] = a.data[row * params.K + tile_k + local_x];
        else
            tile_a[local_y][local_x] = float16_t(0.0);
            
        if (tile_k + local_y < params.K)
            tile_b[local_y][local_x] = b.data[(tile_k + local_y) * params.N + col];
        else
            tile_b[local_y][local_x] = float16_t(0.0);
        
        barrier();
        
        // Compute partial dot product
        for (uint k = 0; k < 32; k++) {
            acc += tile_a[local_y][k] * tile_b[k][local_x];
        }
        
        barrier();
    }
    
    c.data[row * params.N + col] = acc;
}
```

### Executor Update
```cpp
bool VulkanExecutor::ExecuteMatMulTiled(
    const std::vector<float>& A,
    const std::vector<float>& B,
    std::vector<float>& C,
    uint32_t M, uint32_t K, uint32_t N) {
    
    // Use tiled pipeline
    auto it = pipelines_.find("matmul_fp16_tile32");
    if (it == pipelines_.end()) return false;
    
    // Dispatch 2D workgroups
    uint32_t groups_x = (N + 31) / 32;
    uint32_t groups_y = (M + 31) / 32;
    
    vkCmdDispatch(commandBuffer, groups_x, groups_y, 1);
    
    return true;
}
```

## Testing Plan

### Unit Test
```cpp
TEST(MatMulTiled, Correctness) {
    std::vector<float> A(4096 * 4096);
    std::vector<float> B(4096 * 4096);
    std::vector<float> C(4096 * 4096);
    std::vector<float> C_ref(4096 * 4096);
    
    // Fill with test data
    // Compute reference on CPU
    // Run tiled kernel
    // Compare results (allow small FP16 error)
}
```

### Performance Test
```cpp
TEST(MatMulTiled, Performance) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        executor.ExecuteMatMulTiled(A, B, C, 4096, 4096, 4096);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto ms = std::chrono::duration<float, std::milli>(end - start).count() / 100;
    EXPECT_LT(ms, 30.0f);  // Must be under 30ms
}
```

## Risk Mitigation

### Risk: Shader Compilation Fails
**Mitigation**: Keep old shader as fallback
```cpp
if (!CreateComputePipeline("matmul_fp16_tile32", ...)) {
    std::cerr << "Tiled shader failed, using fallback\n";
    return CreateComputePipeline("matmul_fp16", ...);
}
```

### Risk: Incorrect Results
**Mitigation**: Extensive testing with known outputs
- Compare against CPU reference
- Test edge cases (small matrices, non-power-of-2)
- Validate with different random seeds

### Risk: Performance Not Improved
**Mitigation**: Profile with GPU counters
- Use Radeon GPU Profiler
- Check memory bandwidth utilization
- Verify occupancy

## Success Criteria

### Must Have
- [ ] Tiled MatMul kernel compiles
- [ ] Results match CPU reference within FP16 epsilon
- [ ] 4096x4096 completes in <50ms (9x speedup)

### Should Have
- [ ] <30ms for 4096x4096 (14x speedup)
- [ ] All test cases pass
- [ ] Integrated into transformer pipeline

### Nice to Have
- [ ] <20ms for 4096x4096 (22x speedup)
- [ ] Vectorized loads (vec4)
- [ ] RDNA3 wave32 mode

## Timeline

| Task | Time | Status |
|------|------|--------|
| Create tiled shader | 30 min | ⏳ Not started |
| Update executor | 30 min | ⏳ Not started |
| Benchmark | 15 min | ⏳ Not started |
| Integrate | 15 min | ⏳ Not started |
| **Total** | **90 min** | **~1.5 hours** |

## Next Actions

1. **Create `matmul_fp16_tile32.comp`** with 32x32 tiles
2. **Compile to SPIR-V** using glslangValidator
3. **Update executor** to use tiled dispatch
4. **Run benchmark** and verify speedup
5. **Integrate** into transformer pipeline

## Conclusion

This single optimization (tiled MatMul) will provide **15x speedup**, bringing us from 0.35 TPS to ~5 TPS. Combined with weight pre-upload (Phase 2), we'll reach **35 TPS**. With all 5 phases, we hit **195 TPS** - nearly double our target.

The infrastructure is ready. The shader template exists. Let's implement it.
