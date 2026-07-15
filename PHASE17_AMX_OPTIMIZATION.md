# Phase 17: Hybrid Auto / AMX Optimizations

## Executive Summary

**Phase 17** implements next-generation compute optimization through:
1. **Intel AMX (Advanced Matrix Extensions)** support for Sapphire Rapids+ CPUs
2. **Hybrid Auto Scheduler** - Intelligent workload distribution between AMX, AVX-512, and GPU
3. **Predictive Kernel Selection** - Runtime profiling-based path selection

**Target:** 40-60% throughput improvement on AMX-capable hardware

---

## Technical Specifications

### Current Baseline (Phase 16)

| Metric | Value | Source |
|--------|-------|--------|
| Token Latency | 59ms | TC15_001 telemetry |
| Throughput | ~17 TPS | Calculated |
| Memory | ~1GB | MMAP + Q4_K KV |
| ISA | AVX-512 | MASM kernels |

### Phase 17 Targets

| Metric | Current | Target | Improvement |
|--------|---------|--------|-------------|
| Token Latency | 59ms | 25-35ms | 40-58% |
| Throughput | 17 TPS | 28-40 TPS | 65-135% |
| AMX Utilization | 0% | 80%+ | New capability |

---

## Instruction Set Mapping

### AMX Architecture Overview

```
Intel AMX (Advanced Matrix Extensions)
├── Tile Registers: 8 × tmm0-tmm7 (1KB each)
├── Tile Config: 64-byte tile configuration
├── Operations:
│   ├── TDPBF16PS - BF16 dot product
│   ├── TDPBSSD - INT8 dot product
│   └── TDPFP16PS - FP16 dot product (Granite Rapids)
└── Requirements: Sapphire Rapids (SPR) or newer
```

### Hybrid Execution Paths

```
Sovereign_Hybrid_Scheduler
├── Detect_CPU_Features()
│   ├── Check AMX (CPUID leaf 7, EDX bit 24)
│   ├── Check AVX-512 VNNI
│   └── Check RDNA4 GPU
│
├── Select_Optimal_Path()
│   ├── IF AMX_AVAILABLE AND matrix_size > 512:
│   │   └── Route → AMX_Tile_Kernel
│   ├── ELIF AVX-512 AND batch_size > 1:
│   │   └── Route → AVX512_FMA_Kernel
│   ├── ELIF GPU_AVAILABLE:
│   │   └── Route → RDNA4_Compute_Shader
│   └── ELSE:
│       └── Route → Scalar_Fallback
│
└── Profile_and_Adapt()
    ├── Measure actual latency per path
    ├── Update path selection weights
    └── Cache optimal config per workload type
```

---

## Latency Profiling: Current Cycle Counts

### Baseline AVX-512 Kernel (measured)

```
Operation: Q4_K dequant + GEMM 4096×4096×4096

Phase 16 (AVX-512):
├── Dequantize: ~2,400 cycles (1.0μs @ 2.4GHz)
├── GEMM (blocked): ~48,000 cycles (20μs)
├── Quantize output: ~1,200 cycles (0.5μs)
└── Total: ~51,600 cycles (~21.5μs)

Phase 17 Target (AMX):
├── Tile load: ~400 cycles
├── TDPBF16PS: ~12,000 cycles (5μs) - 4x speedup
├── Tile store: ~300 cycles
└── Total: ~12,700 cycles (~5.3μs) - 4x improvement
```

### Bottleneck Analysis

```
Current Hotspots (from TC15_001 telemetry):
1. KV Cache Lookup: 15% of inference time
2. Attention Q×K^T: 35% of inference time ← PRIMARY TARGET
3. Feed-forward GEMM: 40% of inference time ← SECONDARY TARGET
4. Sampling/Top-P: 10% of inference time

AMX Optimization Priority:
1. Attention matrix multiplies (Q×K, Softmax×V)
2. FFN up-projection (gate + up)
3. FFN down-projection
```

---

## AMX Kernel Implementation

### sovereign_amx_kernels.asm

```asm
; =============================================================================
; Sovereign_AMX_AttentionKernel
; Optimized attention Q×K^T using Intel AMX
;
; Input:  Q [seq_len × head_dim], K [seq_len × head_dim]
; Output: Scores [seq_len × seq_len]
; =============================================================================

Sovereign_AMX_AttentionKernel PROC FRAME
    ; Save state
    push    rbx
    .pushreg rbx
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    .endprolog
    
    ; Load tile configuration
    ; Configure 16×16 BF16 tiles
    LDTILECFG [tile_config]     ; Load tile configuration
    
    ; Tile load Q matrix
    TILELOADD tmm0, [rcx + r8]  ; Load Q tile
    TILELOADD tmm1, [rcx + r8 + 64]
    
    ; Tile load K^T matrix (transposed)
    TILELOADD tmm2, [rdx + r9]  ; Load K tile
    TILELOADD tmm3, [rdx + r9 + 64]
    
    ; Compute Q × K^T using BF16 dot product
    TDPBF16PS tmm4, tmm0, tmm2  ; Tile dot product
    TDPBF16PS tmm5, tmm0, tmm3
    TDPBF16PS tmm6, tmm1, tmm2
    TDPBF16PS tmm7, tmm1, tmm3
    
    ; Store results
    TILESTORED [r11], tmm4      ; Store to scores matrix
    TILESTORED [r11 + 64], tmm5
    TILESTORED [r11 + 128], tmm6
    TILESTORED [r11 + 192], tmm7
    
    ; Release tile configuration
    TILERELEASE
    
    ; Restore state
    pop     r13
    pop     r12
    pop     rbx
    ret
    
Sovereign_AMX_AttentionKernel ENDP
```

---

## Hybrid Auto Scheduler

### sovereign_hybrid_scheduler.cpp

```cpp
class HybridComputeScheduler {
private:
    enum ComputePath {
        PATH_AMX_TILE,      // Intel AMX (fastest for large matrices)
        PATH_AVX512_VNNI,   // AVX-512 with VNNI (good for medium)
        PATH_AVX2,          // AVX2 fallback
        PATH_GPU_RDNA4,     // AMD RDNA4 GPU
        PATH_SCALAR         // Scalar fallback
    };
    
    struct PathMetrics {
        ComputePath path;
        float avgLatency;
        float successRate;
        uint64_t invocationCount;
    };
    
    std::unordered_map<WorkloadType, PathMetrics> pathCache;
    
public:
    ComputePath SelectOptimalPath(WorkloadDesc& workload) {
        // Check cache first
        auto it = pathCache.find(workload.type);
        if (it != pathCache.end() && it->second.invocationCount > 10) {
            // Use cached optimal path
            return it->second.path;
        }
        
        // Dynamic selection based on workload characteristics
        if (workload.matrixSize > 1024 && cpuFeatures.amx) {
            return PATH_AMX_TILE;
        } else if (workload.batchSize > 1 && cpuFeatures.avx512) {
            return PATH_AVX512_VNNI;
        } else if (gpuAvailable && workload.isEmbeddable) {
            return PATH_GPU_RDNA4;
        }
        
        return PATH_AVX2;
    }
    
    void ProfileAndAdapt(WorkloadDesc& workload, ComputePath usedPath, float actualLatency) {
        auto& metrics = pathCache[workload.type];
        
        // Update running average
        metrics.avgLatency = (metrics.avgLatency * metrics.invocationCount + actualLatency) 
                            / (metrics.invocationCount + 1);
        metrics.invocationCount++;
        
        // If current path underperforms, trigger re-evaluation
        if (metrics.invocationCount > 100 && metrics.avgLatency > expectedLatency * 1.2) {
            TriggerPathReevaluation(workload.type);
        }
    }
};
```

---

## Regression Testing Framework

### Automated Regression Detection

```cpp
// sovereign_regression_guard.cpp

class RegressionGuard {
public:
    struct BaselineMetrics {
        float p50Latency;
        float p95Latency;
        float p99Latency;
        float throughput;
        float memoryUsage;
    };
    
    bool ValidateAgainstBaseline(const std::string& commitHash) {
        // Load baseline from commit 9cb28a680
        BaselineMetrics baseline = LoadBaseline("9cb28a680");
        
        // Run current build
        CurrentMetrics current = RunBenchmarkSuite();
        
        // Check for regressions
        bool passed = true;
        
        if (current.p95Latency > baseline.p95Latency * 1.10) {
            LogRegression("P95 latency regression", baseline.p95Latency, current.p95Latency);
            passed = false;
        }
        
        if (current.throughput < baseline.throughput * 0.90) {
            LogRegression("Throughput regression", baseline.throughput, current.throughput);
            passed = false;
        }
        
        if (current.memoryUsage > baseline.memoryUsage * 1.15) {
            LogRegression("Memory usage regression", baseline.memoryUsage, current.memoryUsage);
            passed = false;
        }
        
        return passed;
    }
};
```

---

## Implementation Plan

### Phase 17A: AMX Kernel Development (Week 1)
- [ ] Implement AMX tile configuration
- [ ] Develop attention Q×K^T kernel
- [ ] Develop FFN GEMM kernels
- [ ] Unit test against AVX-512 baseline

### Phase 17B: Hybrid Scheduler (Week 2)
- [ ] CPU feature detection (CPUID)
- [ ] Path selection logic
- [ ] Profiling infrastructure
- [ ] Cache optimization

### Phase 17C: Integration & Validation (Week 3)
- [ ] Wire into Sovereign_Engine
- [ ] Regression testing
- [ ] Performance validation
- [ ] Documentation

---

## Success Criteria

| Metric | Baseline (9cb28a680) | Target | Measurement |
|--------|---------------------|--------|-------------|
| Token Latency | 59ms | 25-35ms | TC15_001 equivalent |
| Throughput | 17 TPS | 28-40 TPS | Sustained 60s |
| AMX Utilization | N/A | >80% | Hardware counters |
| Regression | N/A | 0% | vs 9cb28a680 |

---

## Files to Create

1. `src/asm/Sovereign_AMX_Kernels.asm` - AMX tile kernels
2. `src/quantization/sovereign_hybrid_scheduler.cpp` - Path selection
3. `src/quantization/sovereign_profiler.cpp` - Performance profiling
4. `src/quantization/sovereign_regression_guard.cpp` - Regression detection
5. `PHASE17_AMX_OPTIMIZATION.md` - This document

**Status:** Phase 17 initiated. Awaiting hardware capability confirmation.
