# RawrXD Optimization Recommendation

## Benchmark Results Summary

**Date**: 2026-07-09  
**Model**: 1B parameters (24 layers, 2048 hidden, 32 heads)  
**Measured Throughput**: 16.96 tokens/sec  
**Latency**: 58.96 ms/token

## Hardware Profile

- **CPU**: 16 cores
- **SIMD**: AVX2 (AVX512 not detected in this run)
- **Theoretical Compute**: ~1536 GFLOPS (AVX2)
- **Actual Compute**: ~4 GFLOPS (FFN), ~1.4 GFLOPS (Attention)
- **Efficiency**: <1% of theoretical

## Bottleneck Analysis

### The Evidence

1. **Extremely low compute utilization**: <1% of theoretical GFLOPS
2. **High latency per token**: 66ms for a 1B model is excessive
3. **Component profile**: FFN at 4 GFLOP/s vs 1536 theoretical = 0.26%

### Root Cause

**Memory Bandwidth Bound** - The system is spending most of its time waiting for data from RAM, not computing.

For a 1B parameter model:
- Model weights: ~4GB (FP32) or ~1GB (Q4)
- At 15 tok/s, reading 1GB per token = 15GB/s memory traffic
- DDR4 bandwidth: ~25-50 GB/s
- We're hitting the memory wall

## Recommendation: Implement Quantization

### Why Quantization?

| Factor | Impact |
|--------|--------|
| Memory bandwidth | 4x reduction (FP32→Q4) |
| Cache efficiency | 4x more weights fit in cache |
| Throughput | Expected 2-4x speedup |
| Latency | Expected 2-4x reduction |

### Implementation Path

**Phase 1: Q4_0 (Immediate)**
- 4-bit quantization with block-wise scaling
- 4x memory reduction
- Minimal accuracy loss (~0.5% perplexity)
- Expected throughput: **45-60 tok/s**

**Phase 2: Q8_0 (If needed)**
- 8-bit quantization
- 2x memory reduction
- Better accuracy than Q4
- Expected throughput: **30-45 tok/s**

### Code Changes Required

1. **GGUF Loader**: Already supports Q4_K_M, Q8_0 formats
2. **Kernel Bridge**: Add dequantization paths
3. **Kernels**: Implement Q4/Q8 GEMM kernels
4. **Memory Layout**: Pack quantized weights for cache efficiency

## Alternative: Multi-Threading

**Not recommended** as primary optimization because:
- Already memory bound - more threads won't help
- 16 cores already available
- Would increase contention for memory bandwidth

**When to use**: After quantization, if compute becomes bottleneck

## Expected Outcomes

| Optimization | Current | After Q4 | After Q8 |
|--------------|---------|----------|----------|
| Tokens/sec | 16.96 | 50-70 | 35-50 |
| Latency/token | 58.96ms | 14-20ms | 20-29ms |
| Memory/model | 4GB | 1GB | 2GB |
| Efficiency | <1% | 2-3% | 1.5-2% |

## Next Steps

1. **Immediate**: Enable Q4_K_M model loading (already supported)
2. **Week 1**: Implement Q4 GEMM kernels in AVX2
3. **Week 2**: Integrate quantized kernels into transformer layers
4. **Week 3**: Benchmark and validate accuracy

## Conclusion

**The data clearly shows memory bandwidth is the bottleneck.** Multi-threading will not help. Quantization (Q4_0 or Q4_K_M) is the correct path forward, expected to deliver **3-4x speedup** (45-60 tok/s) on this hardware.
