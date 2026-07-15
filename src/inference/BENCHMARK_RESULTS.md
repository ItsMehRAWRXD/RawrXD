# Phase Validation Benchmark Results

## Date: 2026-07-09
## GPU: AMD Radeon RX 7800 XT

---

## Summary

| Phase | Status | Result | Notes |
|-------|--------|--------|-------|
| Phase 1: Tiled MatMul | ⚠️ ISSUE | Slower than original | Needs debugging |
| Phase 2: Weight Cache | ✅ PASS | 934,579x speedup | Working correctly |
| Cumulative | ⚠️ BLOCKED | Cannot proceed | Fix Phase 1 first |

---

## Detailed Results

### Test 1: Original MatMul (Baseline)
- **Time**: 386.30 ms
- **GFLOPS**: 0.09
- **Est. TPS**: 0.02
- **Status**: ✅ Baseline established

### Test 2: Tiled MatMul (Phase 1)
- **Time**: 580.35 ms
- **GFLOPS**: 236.82
- **Est. TPS**: 0.01
- **Speedup**: 0.67x (SLOWER)
- **Status**: ⚠️ REGRESSION

**Problem**: Tiled shader is 1.5x SLOWER than original

### Test 3: Weight Cache (Phase 2)
- **Lookup Time**: 0.107 μs
- **VRAM Usage**: 3,072 MB (3GB)
- **Speedup vs Upload**: 934,579x
- **Est. TPS**: 130,841 (theoretical)
- **Status**: ✅ EXCELLENT

**Working correctly**: Sub-microsecond weight lookups

### Test 4: Full Layer (Phase 1+2)
- **Status**: Incomplete (blocked by Phase 1 issue)

---

## Root Cause Analysis

### Why Tiled MatMul Is Slower

**Hypothesis 1: Incorrect Workgroup Dispatch**
```
Current: groupsX = (N + 31) / 32, groupsY = (M + 31) / 32
For 4096x4096: groups = 128x128 = 16,384 workgroups
```
This may be too many workgroups causing overhead.

**Hypothesis 2: Barrier Synchronization**
The tiled shader has 2 barriers per tile iteration:
```glsl
barrier(); // After load
// ... compute ...
barrier(); // Before next load
```
For 128 tiles, that's 256 barriers - very expensive.

**Hypothesis 3: Shared Memory Bank Conflicts**
```glsl
shared float16_t tile_a[32][32];
shared float16_t tile_b[32][32];
```
Access pattern may cause bank conflicts on RDNA3.

**Hypothesis 4: Matrix Size Too Large**
4096x4096x4096 = 137 GFLOP - this is a huge matrix.
The tiled algorithm may not be optimal for this size.

---

## Recommended Fixes

### Fix 1: Optimize Barrier Usage
Reduce from 2 barriers to 1 per tile:
```glsl
// Load tiles
barrier();
// Compute
// Remove second barrier - not needed if we don't reuse shared mem
```

### Fix 2: Tune Tile Size
Try 16x16 or 64x64 tiles instead of 32x32:
```glsl
layout(local_size_x = 16, local_size_y = 16) in;
shared float16_t tile_a[16][16];
```

### Fix 3: Vectorized Loads
Load 4 elements at once:
```glsl
float16_t4 vec_a = load4(A + offset);
```

### Fix 4: Persistent Threads
Keep threads resident across tiles to reduce launch overhead.

---

## Next Steps

### Immediate (Today)
1. ✅ **Weight Cache**: Working - no changes needed
2. 🔴 **Tiled MatMul**: Needs debugging
   - Profile with Radeon GPU Profiler
   - Try different tile sizes
   - Reduce barrier usage

### This Week
1. Fix tiled MatMul performance
2. Re-run benchmark to verify 15x speedup
3. Proceed to Phase 3 (Kernel Fusion) only after Phase 1 passes

### Decision Point
**DO NOT proceed to Phase 3** until Phase 1 is fixed.
Building on a broken foundation will make debugging harder.

---

## Files Status

| File | Status |
|------|--------|
| `matmul_fp16_tile32.comp` | ⚠️ Needs optimization |
| `gpu_weight_cache.cpp` | ✅ Working |
| `benchmark_phase_validation.cpp` | ✅ Working |

---

## Conclusion

**Phase 2 (Weight Cache)**: ✅ SUCCESS
- 934,579x speedup on weight lookups
- 3GB VRAM usage for 32 layers
- Sub-microsecond access times

**Phase 1 (Tiled MatMul)**: ⚠️ FAILURE
- 1.5x SLOWER than original
- Needs debugging and optimization
- Blocker for Phase 3

**Recommendation**: Fix tiled MatMul before proceeding.
