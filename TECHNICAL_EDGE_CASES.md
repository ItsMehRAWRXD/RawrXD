# RawrXD N-EVM Technical Edge Cases & Safeguards

## Overview

This document captures critical edge cases and implementation safeguards for the RawrXD N-EVM validation pipeline. These insights prevent subtle bugs that can invalidate benchmark results.

---

## 1. Determinism Edge Cases

### 1.1 Parallel Reduction Drift

**Problem:** Non-determinism in native C++ runtimes usually stems from non-associative floating-point addition in multi-threaded reductions.

**Manifests in:**
- OpenMP/pthreads summing GEMM partial products
- Softmax online reductions across SIMD lanes
- Attention score accumulation

**Root Cause:**
```
Thread 1: (a + b) + c = 1.0000001
Thread 2: a + (b + c) = 1.0000002  // Different due to FP associativity
```

**Safeguard:** `nevm_determinism_safeguards.hpp`
- Use tree-based reduction with fixed-size chunks
- Final reduction always sequential
- Consider Kahan summation for critical paths

**Validation:**
```cpp
// Run 10 times, compare outputs
DeterminismValidator::Validate(run1, run2, size, tolerance=1e-5f);
```

---

### 1.2 FMA / AVX Precision Divergence

**Problem:** `vfmadd231ps` (FMA) vs `a * b + c` (separate ops) produce different results due to intermediate rounding.

**Example:**
```cpp
// FMA: single rounding
result = round(a * b + c);

// Separate: double rounding
temp = round(a * b);
result = round(temp + c);
```

**Impact:** Bitwise divergence in logits across different code paths.

**Safeguards:**
1. Disable FMA for determinism-critical paths:
   ```cpp
   _controlfp_s(nullptr, _PC_53, _MCW_PC);
   ```

2. Use explicit multiply-add in GEMM:
   ```cpp
   sum = sum + A[i] * B[i];  // Never use FMA
   ```

3. Document FMA usage in kernel registry:
   ```cpp
   KernelInfo {
       .name = "MatMul_F32",
       .uses_fma = false,  // Required for determinism
       .deterministic = true
   }
   ```

---

## 2. Stress Testing Edge Cases

### 2.1 KV Cache Page Fragmentation

**Problem:** Custom paged attention allocators can fragment over 100+ iterations, causing RSS growth even without leaks.

**Symptoms:**
- RSS grows 5-10% over stress test
- Not a leak (memory reclaimed on exit)
- Caused by page table expansion

**Detection:**
```cpp
// Monitor RSS growth rate, not absolute value
float growth_rate = (current_rss - baseline_rss) / baseline_rss;
if (growth_rate > 0.15f) {  // 15% threshold
    // Likely fragmentation, not leak
}
```

**Mitigation:**
- Pre-allocate KV cache pages at startup
- Use fixed-size page pools
- Monitor page table size separately from RSS

---

### 2.2 Execution Plan Freshness

**Problem:** Dynamic executor may cache bindings that become invalid when:
- Batch dimensions change
- Prompt sequence length changes
- KV page assignments change mid-stream

**Symptoms:**
- Intermittent crashes after N tokens
- Wrong outputs after context switch
- Memory access violations

**Safeguards:**
```cpp
// Invalidate cache when any of these change
struct ExecutionContext {
    int batch_size;
    int seq_length;
    uint64_t kv_page_assignment;
    
    bool operator!=(const ExecutionContext& other) {
        return batch_size != other.batch_size ||
               seq_length != other.seq_length ||
               kv_page_assignment != other.kv_page_assignment;
    }
};

// Check freshness before each layer
if (current_context != cached_context) {
    RebindExecutionPlan();
}
```

---

### 2.3 OS-Level Virtual Memory Overhead

**Problem:** `madvise` thrashing or page table expansion during long-context decodes.

**Symptoms:**
- Sudden latency spikes every N tokens
- RSS jumps discontinuously
- Performance degrades over time

**Detection:**
```cpp
// Monitor page faults
MEMORYSTATUSEX mem;
GlobalMemoryStatusEx(&mem);
if (mem.PageFaultCount - last_page_faults > threshold) {
    // OS-level paging activity
}
```

**Mitigation:**
- Lock critical pages in memory (mlock)
- Pre-fault all model weights at load
- Use huge pages for KV cache

---

## 3. Performance Budget Edge Cases

### 3.1 Prefill vs Decode Profiles

**Critical Distinction:**

| Phase | Bottleneck | MatMul % | Optimization Target |
|-------|------------|----------|---------------------|
| **Prefill** | Compute-bound | ~82% | Larger tiles, kernel fusion |
| **Decode** | Memory-bandwidth | ~40-60% | Weight streaming, cache efficiency |

**Common Mistake:** Optimizing for prefill profile when deployment is decode-heavy.

**Safeguard:**
```cpp
// Always profile both phases separately
PerformanceBudget prefill_budget = AnalyzePrefill(...);
PerformanceBudget decode_budget = AnalyzeDecode(...);

// Report both
std::cout << "Prefill MatMul %: " << prefill_budget.matmul_percentage;
std::cout << "Decode MatMul %: " << decode_budget.matmul_percentage;
```

**Expected Decode Shift:**
- MatMul drops from ~82% to ~40-60%
- Memory transfer increases
- Attention becomes more significant

---

### 3.2 Weight Transfer Overhead

**Problem:** If MatMul still dominates during decode, verify:
1. Weight transfers from disk/VRAM to cache
2. Un-vectorized memory layout overheads
3. TLB misses from scattered weight access

**Detection:**
```cpp
// Profile memory vs compute time
auto mem_start = std::chrono::high_resolution_clock::now();
LoadWeightsToCache(weights);
auto mem_end = std::chrono::high_resolution_clock::now();

auto compute_start = std::chrono::high_resolution_clock::now();
RunMatMul(...);
auto compute_end = std::chrono::high_resolution_clock::now();

float mem_time = mem_end - mem_start;
float compute_time = compute_end - compute_start;

if (mem_time > compute_time * 0.5f) {
    // Memory transfer is bottleneck, not compute
}
```

---

## 4. Validation Checklist

Before trusting any benchmark result, verify:

### Correctness Gates
- [ ] Logit validation passes (Top-1 > 99%)
- [ ] Determinism: 0 divergence across 10 runs
- [ ] No NaN/Inf in 1000+ tokens
- [ ] Top-5 agreement > 99.9%

### Stability Gates
- [ ] RSS growth < 10% over stress test
- [ ] Throughput variance < 5% (p95/p99)
- [ ] No page fault spikes
- [ ] KV cache remains valid

### Performance Gates
- [ ] Prefill and decode profiles measured separately
- [ ] MatMul % drops appropriately in decode
- [ ] Dispatch overhead < 2%
- [ ] Memory transfer not dominating compute

---

## 5. Benchmark Report Template

```
================================================================================
RawrXD N-EVM Benchmark Report
================================================================================

BUILD METADATA
--------------
Git Commit:        abc1234
Compiler:          MSVC 14.50
ISA:               AVX-512
CPU:               Ryzen 9 9950X
Model:             Phi-3 Mini Q4_K_M
Context:           4096
Threads:           16

CORRECTNESS GATES
-----------------
Logits Top-1:      99.8%    [PASS]
Logits Top-5:      100%     [PASS]
Determinism:       0/10     [PASS]
NaN/Inf:           0        [PASS]

STABILITY GATES
---------------
RSS Growth:        2.1%     [PASS]
Throughput σ²:     3.2%     [PASS]
Page Faults:       124      [PASS]
KV Cache Valid:    Yes      [PASS]

PERFORMANCE BUDGET (Prefill)
----------------------------
MatMul:            82.3%    [OK]
Attention:         9.1%     [OK]
Sampling:          3.0%     [OK]
Dispatch:          1.8%     [OK]
Other:             3.8%     [OK]

PERFORMANCE BUDGET (Decode)
---------------------------
MatMul:            48.7%    [OK]  ← Dropped as expected
Attention:         28.3%    [OK]  ← Increased as expected
Sampling:          12.1%    [OK]
Dispatch:          4.2%     [OK]
Memory Transfer:   6.7%     [OK]

LATENCY METRICS
---------------
Mean:              45.2 ms
Median:            43.1 ms
p95:               51.2 ms
p99:               58.7 ms
Max:               97.3 ms

OVERALL
-------
Throughput:        38.5 tok/s
Memory:            9.2 GB
Status:            ALL GATES PASS
================================================================================
```

---

## 6. Quick Reference: Debugging Divergence

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Logits differ at token 0 | FMA precision | Disable FMA, use explicit mul-add |
| Logits differ after N tokens | Execution plan stale | Invalidate cache on context change |
| RSS grows continuously | Memory leak | Check allocator, use address sanitizer |
| RSS grows then stabilizes | Page fragmentation | Pre-allocate, use huge pages |
| MatMul % > 80% in decode | Weight transfer overhead | Profile memory vs compute |
| Throughput variance > 10% | OS scheduling | Pin threads, disable power management |
| p99 latency spikes | Page faults | Lock pages, pre-fault weights |

---

## 7. Implementation Priority

**Must Have (Blocks Production):**
1. Determinism safeguards (FMA control, tree reduction)
2. Execution plan freshness checks
3. Separate prefill/decode profiling

**Should Have (Performance Validation):**
4. KV cache page fragmentation monitoring
5. Memory transfer vs compute profiling
6. Page fault tracking

**Nice to Have (Deep Debugging):**
7. SIMD lane divergence detection
8. Cache miss profiling per kernel
9. TLB miss tracking
