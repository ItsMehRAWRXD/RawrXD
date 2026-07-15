# Path to 100+ tok/s on RX 7800 XT

## Current Status Summary

### ✅ What's Working
1. **Vulkan GPU Infrastructure**
   - RX 7800 XT detected and initialized
   - FP16 compute shaders compiled and loaded
   - All 4 kernels operational (RMSNorm, Softmax, MatMul, VerifyCandidates)

2. **Kernel Validation**
   - RMSNorm: ✅ 2.3ms for 4096 elements
   - Softmax: ✅ 10.5ms for 512x512
   - MatMul: ⚠️ 433ms for 4096x4096 (NEEDS OPTIMIZATION)

3. **Benchmark Infrastructure**
   - Realistic transformer timing
   - Performance analysis tools
   - Context scaling analysis

### 🔴 Current Bottlenecks

#### Primary: MatMul Kernel (200x too slow)
- **Current**: 433ms for 4096x4096
- **Required**: 1-2ms for 4096x4096
- **Impact**: 57 seconds per forward pass

#### Secondary: Memory Transfers
- Uploading/downloading for every operation
- No persistent weight storage in VRAM
- Buffer allocation/deallocation overhead

#### Tertiary: Kernel Launch Overhead
- Descriptor set allocation per call
- Command buffer recording
- GPU synchronization after each kernel

---

## The 5-Phase Optimization Plan

### Phase 1: Tiled MatMul Kernel (15x speedup)
**Goal**: Reduce 4096x4096 MatMul from 433ms to ~30ms

#### Implementation Steps
1. **Create tiled compute shader** (`matmul_fp16_tile32.comp`)
   - 32x32 thread blocks
   - Shared memory for tiles
   - Vectorized loads (vec4)

2. **Optimize for RDNA3**
   - Wave32 execution mode
   - LDS banking optimization
   - Coalesced memory access

3. **Benchmark**
   - Target: <30ms for 4096x4096
   - Verify correctness
   - Profile with Radeon GPU Profiler

#### Expected Impact
- MatMul: 433ms → 30ms (14x faster)
- Layer time: 225ms → 50ms
- Base TPS: 0.14 → 2.0

### Phase 2: Weight Pre-Upload (7x speedup)
**Goal**: Eliminate CPU→GPU memory transfers

#### Implementation Steps
1. **Create weight upload system**
   ```cpp
   class GPUWeightCache {
       std::unordered_map<std::string, VulkanBuffer> weights;
       bool UploadWeights(const Model& model);
       VulkanBuffer* GetWeight(const std::string& name);
   };
   ```

2. **Modify executor to use cached weights**
   - Remove upload from ExecuteMatMul
   - Reference cached buffers by name
   - Lazy loading for unused layers

3. **KV Cache on GPU**
   - Allocate persistent KV cache in VRAM
   - Update in-place during generation
   - Double buffering for async operations

#### Expected Impact
- Eliminate upload overhead: ~100ms per layer
- Layer time: 50ms → 15ms
- Base TPS: 2.0 → 14.0

### Phase 3: Kernel Fusion (2.5x speedup)
**Goal**: Reduce kernel launch overhead

#### Implementation Steps
1. **Fused QKV Projection**
   - Single kernel for Q, K, V
   - Shared input loading
   - Coalesced output writes

2. **Fused Attention**
   - Q×K^T + Softmax + ×V in one kernel
   - Flash Attention-style algorithm
   - Tiled computation

3. **Fused FFN**
   - Gate + Up + Down projections
   - SiLU activation fused
   - Residual connection

#### Expected Impact
- Kernel launches: 128 → 32 per layer
- Layer time: 15ms → 8ms
- Base TPS: 14.0 → 26.0

### Phase 4: Medusa Speculative Decoding (2.5x speedup)
**Goal**: Generate multiple tokens per forward pass

#### Implementation Steps
1. **Draft Model**
   - Smaller model (1-2B parameters)
   - Runs on same GPU
   - Generates 4-8 candidate tokens

2. **Tree Verification**
   - Verify candidates in parallel
   - Batch size = num_candidates
   - Accept/reject based on target probabilities

3. **Acceptance Rate Optimization**
   - Target 65%+ acceptance
   - Temperature tuning
   - Top-p filtering

#### Expected Impact
- Tokens per forward: 1 → 2.5
- Effective TPS: 26.0 → 65.0

### Phase 5: Quantization (3x speedup)
**Goal**: Reduce memory bandwidth and increase compute density

#### Implementation Steps
1. **FP8 Compute**
   - Use VK_KHR_shader_float8 extension
   - Mixed precision: FP8 for FFN, FP16 for attention
   - 2x memory bandwidth reduction

2. **INT4 Weights**
   - Dequantize on-the-fly in shader
   - 4x memory bandwidth reduction
   - Minimal accuracy loss

3. **Mixed Precision**
   - Activations: FP16
   - Weights: INT4
   - Compute: FP8 where possible

#### Expected Impact
- Memory bandwidth: 624 GB/s → 156 GB/s effective
- Compute density: 2x higher
- Final TPS: 65.0 → 195.0

---

## Cumulative Performance Projection

| Phase | Speedup | Base TPS | Medusa TPS |
|-------|---------|----------|------------|
| Current | 1x | 0.14 | 0.35 |
| Phase 1: Tiled MatMul | 15x | 2.0 | 5.0 |
| Phase 2: Weight Upload | 7x | 14.0 | 35.0 |
| Phase 3: Kernel Fusion | 2.5x | 26.0 | 65.0 |
| Phase 4: Medusa | 2.5x | 26.0 | 162.5 |
| Phase 5: Quantization | 3x | 78.0 | 195.0 |

**Conservative target: 100+ tok/s**
**Optimistic target: 150-200 tok/s**

---

## Implementation Priority

### Week 1: Critical Path
- [ ] Implement tiled MatMul kernel
- [ ] Add weight pre-upload system
- [ ] Profile with GPU counters

### Week 2: High Impact
- [ ] Implement KV cache on GPU
- [ ] Fuse QKV projections
- [ ] Optimize buffer management

### Week 3: Polish
- [ ] Implement Medusa draft model
- [ ] Add tree verification
- [ ] Tune acceptance rates

### Week 4: Advanced
- [ ] Add FP8 compute shaders
- [ ] Implement INT4 dequantization
- [ ] Final benchmarking

---

## Key Metrics to Track

### Per-Layer Performance
- MatMul time (target: <5ms for 4096x4096)
- RMSNorm time (target: <1ms)
- Softmax time (target: <2ms)
- Total layer time (target: <10ms)

### Full Model Performance
- Forward pass time (target: <320ms for 32 layers)
- Base TPS (target: >3.0)
- With Medusa (target: >100)

### Resource Utilization
- GPU compute utilization (target: >80%)
- Memory bandwidth (target: >500 GB/s)
- VRAM usage (target: <14GB)

---

## Success Criteria

### Minimum Viable
- 50 tok/s at 32K context
- All kernels working
- Weight pre-upload implemented

### Target
- 100 tok/s at 32K context
- Medusa speculative decoding
- Kernel fusion

### Stretch
- 150+ tok/s at 32K context
- FP8 compute
- INT4 weights

---

## Conclusion

The path to 100+ tok/s is clear and achievable:

1. **Tiled MatMul** is the highest-impact optimization (15x)
2. **Weight pre-upload** eliminates major bottleneck (7x)
3. **Kernel fusion** and **Medusa** provide additional 6x
4. **Quantization** pushes us well beyond target (3x)

With all optimizations: **195 tok/s at 32K context**

The infrastructure is in place. The kernels are working. Now it's about optimization.
