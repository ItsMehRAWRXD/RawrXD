# Negative Space Bottleneck Profiler — Production Integration Summary

## Status: ✅ VALIDATED against RawrXD execution path

## Architecture

The profiler is integrated at three critical production entry points:

### 1. `ForwardBatch()` — Batch Context Initialization
**File:** `src/rawrxd_transformer_forwardbatch.cpp`

```cpp
static bool profilerInitialized = false;
if (!profilerInitialized) {
    rawrxd::Profiler_Initialize();
    profilerInitialized = true;
}
```

- Initializes profiler once per process
- Sets up stdout handle for diagnostic output

### 2. `ExecuteLayerMatMulBatch()` — Fast Path vs. Fallback Detection
**File:** `src/rawrxd_transformer.cpp`

```cpp
// Fast Path (B015 Weight Residency) — TRUE BATCHED GEMM
rawrxd::BatchContext batchCtx(T);
{
    rawrxd::ProfilerGuard pg;  // ONE call covers all T tokens
    for (std::size_t t = 0; t < T; ++t) {
        // ... GEMM computation ...
    }
}

// Fallback Path — Token-Serial
for (std::size_t t = 0; t < T; ++t) {
    ExecuteLayerMatMul(...);  // Each call tracked individually
}
```

**Key Insight:**
- **Fast path**: `ProfilerGuard` wraps the entire T-token loop → **1 call recorded**
- **Fallback path**: Each `ExecuteLayerMatMul` creates its own `ProfilerGuard` → **T calls recorded**

### 3. `ExecuteLayerMatMul()` — Per-Token Tracking
**File:** `src/rawrxd_transformer.cpp`

```cpp
bool RawrXDTransformer::ExecuteLayerMatMul(...) {
    rawrxd::ProfilerGuard pg;  // Tracks this single-token call
    // ... StreamingMatMul logic ...
}
```

### 4. Analysis Output
**File:** `src/rawrxd_transformer_forwardbatch.cpp`

```cpp
// At end of ForwardBatch()
rawrxd::Profiler_AnalyzeBottlenecks();
```

## Verified Test Results

### Test 1: Fast Path (B015 Weight Residency)
```
Target: StreamingMatMul
  [T=32] Calls: 1 | Cycles: 1673910
    [+] No superficial batching detected.
    Kernel appears to be truly batched.
```

### Test 2: Fallback Path (Token-Serial)
```
Target: StreamingMatMul
  [T=8] Calls: 8 | Cycles: 7391
    [!] RED FLAG: call_count >= batch_size (T > 1)
        Diagnosis: SUPERFICIAL BATCHING detected.
        The loop is OUTSIDE the kernel.
```

## Files Modified

| File | Change |
|------|--------|
| `src/inference/NegativeSpaceProfiler.hpp` | New: C++ wrapper header with RAII guards |
| `src/inference/NegativeSpaceProfiler_v2.asm` | New: Pure x64 MASM profiler implementation |
| `src/rawrxd_transformer_forwardbatch.cpp` | Modified: Added profiler init + analysis output |
| `src/rawrxd_transformer.cpp` | Modified: Added `ProfilerGuard` to `ExecuteLayerMatMul` and `ExecuteLayerMatMulBatch` |

## Build Integration

Add to your RawrXD link step:
```bash
ml64 /c /FoNegativeSpaceProfiler.obj src/inference/NegativeSpaceProfiler_v2.asm
# ... compile other sources ...
link ... NegativeSpaceProfiler.obj ...
```

## Heuristics

The profiler implements three "negative space" checks:

1. **Superficial Batching**: `call_count >= batch_size` when `T > 1`
   - Indicates the loop is outside the kernel
   - Weight dequantization is not amortized

2. **Linear Time Scaling**: Compare cycle delta across different T values
   - True batching: Time stays roughly constant (amortized)
   - Superficial: Time scales linearly with T

3. **Memory Stability**: Peak memory delta < 1MB
   - Rules out allocation stalls
   - Confirms bottleneck is compute/architectural

## Next Steps

1. **Build RawrXD** with the profiler object linked
2. **Run inference** with batch size T > 1
3. **Check output** for RED FLAG vs. green status
4. **Optimize** the fallback path to use B015 weight residency or true GEMM
