# Path to 150+ tok/s: Maximum Performance Strategy

## Current Status

| Configuration | Throughput | Target |
|--------------|------------|--------|
| CPU (INT8 + MT) | ~87 tok/s | Baseline |
| GPU (Vulkan/HIP) | ??? tok/s | **150+ tok/s** |

## The Gap to Qwen3-30B-A3B (157 tok/s)

### Why We're Close
- **Qwen3-30B** uses GPU (likely A100/H100)
- **We have**: RX 7800XT with 16GB VRAM + RawrXD's Vulkan/HIP backends
- **7800XT specs**: 60 CUs, 3840 stream processors, 16GB GDDR6 @ 19.5 Gbps
- **Theoretical**: ~40 TFLOPS FP16 - enough for 150+ tok/s

## Implementation Strategy

### Phase 1: GPU Backend Integration (Target: 120 tok/s)

**Files to integrate:**
- `rawrxd/src/vulkan_inference_engine.cpp` - Existing Vulkan backend
- `rawrxd/src/hip_inference_engine.cpp` - Existing HIP backend  
- `rawrxd/src/inference/vulkan_mm.cpp` - Matrix multiply kernels
- `rawrxd/src/inference/flash_attention_vulkan_fp8.cpp` - Attention kernels

**Key integration points:**
```cpp
// Use RawrXD's existing Vulkan compute
#include "rawrxd/src/vulkan_compute.h"

// Matrix multiply via Vulkan
vulkan_matmul(q_buffer, k_buffer, attn_buffer, ...);

// Flash Attention via Vulkan
flash_attention_vulkan(q, k, v, out, num_heads, seq_len, head_dim);
```

### Phase 2: Optimized Kernels (Target: 150 tok/s)

**Optimizations:**
1. **FP16/BF16 weights** - 2x memory bandwidth
2. **Cooperative groups** - Better GPU utilization
3. **Tensor cores** - Via Vulkan VK_KHR_cooperative_matrix
4. **Fused kernels** - MatMul + SiLU in single dispatch
5. **Persistent threads** - Keep weights in shared memory

### Phase 3: Medusa on GPU (Target: 200+ tok/s)

**Speculative decoding on GPU:**
- Draft 8 tokens in parallel on GPU
- Verify with single kernel launch
- Tree attention for parallel verification

## Quick Implementation

### Option A: Use RawrXD's Existing Infrastructure

RawrXD already has:
- ✅ Vulkan compute backend
- ✅ HIP backend for AMD
- ✅ Flash Attention Vulkan kernels
- ✅ GGML-Vulkan integration

**Just need to:**
1. Link against RawrXD's existing GPU libraries
2. Use `vulkan_inference_engine` for transformer layers
3. Call `flash_attention_vulkan_fp8` for attention

### Option B: Direct GPU Kernel Implementation

If RawrXD's backends aren't sufficient:

```cpp
// Custom HIP kernel for RX 7800XT
__kernel void transformer_layer(
    __global float* input,
    __global float* weights_q,
    __global float* output,
    uint hidden_size
) {
    // Use RDNA3 wave64 mode
    // Leverage matrix cores
    // Optimize for 7800XT cache hierarchy
}
```

## Expected Performance

| Stage | Throughput | Speedup |
|-------|------------|---------|
| CPU (current) | 87 tok/s | 1x |
| GPU Basic | 120 tok/s | 1.4x |
| GPU Optimized | 150 tok/s | 1.7x |
| GPU + Medusa | 200+ tok/s | 2.3x |

## Next Steps

1. **Test RawrXD's Vulkan backend** - See if it works out of the box
2. **Profile GPU utilization** - Check if we're memory or compute bound
3. **Implement fused kernels** - MatMul + activation fusion
4. **Add Medusa heads** - Speculative decoding on GPU

## The RX 7800XT Advantage

- **16GB VRAM** - Fits 7B model with KV cache
- **60 CUs @ 2.4GHz** - Massive parallel compute
- **Infinity Cache** - 96MB L3 reduces memory bandwidth pressure
- **RDNA3 Architecture** - Optimized for ML workloads

**Bottom line**: With proper GPU kernel optimization, 150+ tok/s is absolutely achievable on the 7800XT!
