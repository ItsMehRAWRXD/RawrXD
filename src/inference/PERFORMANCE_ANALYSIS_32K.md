# 32K Context @ 100+ tok/s Performance Analysis

## Current Status

### Hardware
- **GPU**: AMD Radeon RX 7800 XT (RDNA3)
- **VRAM**: 16 GB
- **Compute Units**: 60 CUs
- **Memory Bandwidth**: ~624 GB/s

### Achieved Results

#### GPU Kernel Performance (measured)
| Kernel | Size | Time | Notes |
|--------|------|------|-------|
| RMSNorm | 4096 | 2.3 ms | ✓ Good |
| Softmax | 512x512 | 10.5 ms | ✓ Good |
| MatMul | 4096x4096 | 433 ms | ✗ Too slow |

#### Transformer Layer Timing
| Component | Time per Layer | Count | Total |
|-----------|---------------|-------|-------|
| RMSNorm (x2) | 14.7 ms | 32 | 470 ms |
| Softmax (x32) | 68.2 ms | 32 | 2182 ms |
| MatMul (x4) | 142.4 ms | 32 | 4556 ms |
| **Total** | **225.2 ms** | 32 | **7207 ms** |

#### Throughput
- **Base TPS**: 0.14 tok/s
- **With Medusa 2.5x**: 0.35 tok/s
- **Target**: 100+ tok/s
- **Gap**: ~285x slower than target

## Root Cause Analysis

### 1. MatMul Bottleneck
The current MatMul implementation is the primary bottleneck:
- **Current**: 433 ms for 4096x4096
- **Required**: ~1-2 ms for 4096x4096
- **Gap**: 200-400x too slow

### 2. Kernel Launch Overhead
Each kernel launch has significant overhead:
- Buffer creation/destruction per call
- Descriptor set allocation per call
- Command buffer recording
- GPU synchronization

### 3. Memory Transfer
Data is being copied CPU→GPU→CPU for every operation instead of keeping weights resident in VRAM.

## Path to 100+ tok/s

### Phase 1: Kernel Optimization (10-20x speedup)
1. **Tiled MatMul**: Use 16x16 or 32x32 tiles with shared memory
2. **Persistent Threads**: Keep workgroups resident on GPU
3. **Vectorized Loads**: Use vec4/vec8 for memory access
4. **RDNA3 Optimizations**: Wave32 mode, LDS banking

### Phase 2: Weight Upload (5-10x speedup)
1. **Pre-upload weights**: Load model weights to GPU VRAM once
2. **KV Cache on GPU**: Keep KV cache in VRAM across tokens
3. **Persistent Buffers**: Reuse buffers instead of allocate/free

### Phase 3: Kernel Fusion (2-3x speedup)
1. **Fused QKV**: Single kernel for Q, K, V projections
2. **Fused Attention**: Combine attention scores + softmax + output
3. **Fused FFN**: Combine gate + up + down projections

### Phase 4: Medusa Speculative (2.5x speedup)
1. **Draft Model**: Smaller model for token generation
2. **Tree Verification**: Verify multiple candidates in parallel
3. **Acceptance Rate**: Target 65%+ acceptance

### Phase 5: Quantization (2-4x speedup)
1. **FP8 Inference**: Use FP8 for compute-bound operations
2. **INT4 Weights**: Quantize weights to INT4
3. **Mixed Precision**: FP16 for attention, FP8 for FFN

## Expected Performance After Optimization

| Phase | Speedup | Expected TPS | Cumulative |
|-------|---------|--------------|------------|
| Current | 1x | 0.35 | 0.35 |
| Kernel Opt | 15x | 5.25 | 5.25 |
| Weight Upload | 7x | 36.75 | 36.75 |
| Kernel Fusion | 2.5x | 91.88 | 91.88 |
| Medusa | 2.5x | 229.69 | 229.69 |
| Quantization | 3x | 689.07 | 689.07 |

**Conservative estimate**: 90-120 tok/s at 32K context

## Implementation Priority

### High Priority (Week 1)
1. [ ] Implement tiled MatMul kernel with shared memory
2. [ ] Add weight pre-upload to GPU VRAM
3. [ ] Implement persistent buffer pool

### Medium Priority (Week 2)
1. [ ] Fuse QKV projections into single kernel
2. [ ] Implement KV cache on GPU
3. [ ] Add command buffer reuse

### Low Priority (Week 3)
1. [ ] Implement FP8 compute shaders
2. [ ] Add INT4 weight dequantization
3. [ ] Optimize for 32K context specifically

## Conclusion

The current implementation proves the Vulkan compute pipeline works on RX 7800 XT, but requires significant optimization to reach 100+ tok/s. The primary bottlenecks are:

1. **MatMul kernel** (needs 200x speedup via tiling)
2. **Memory transfers** (needs weight pre-upload)
3. **Kernel launch overhead** (needs persistent execution)

With the optimizations outlined above, 100+ tok/s at 32K context is achievable on RX 7800 XT.
