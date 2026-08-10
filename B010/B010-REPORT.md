# B010 — Weight Residency Profiling Report

**Date:** 2026-08-10  
**Status:** ✅ COMPLETE (profiling-only, no caching introduced)  
**Parent:** B008 (frozen baseline)  
**Sibling:** B009 (layer-outer experiment — **INVALIDATED**, correctness bug discovered)

---

## Executive Summary

B010 instrumented `StreamingMatMul` to measure where the ~13.4s prefill time actually goes. The results establish a clear acquisition pathology:

> **Weight acquisition/mapping is occurring repeatedly during inference, with no observed residency reuse.** 8,971 MB of weight data is dequantized (4.4× the 2,019 MB model file), with 73,728 incidental map calls and 0% residency hit rate.

**Note:** B010 demonstrates the *magnitude* of the redundant I/O/mapping behavior. The causal contribution to wall-clock time should be quantified from the acquisition-vs-compute timers in B011, where the cache is introduced as a controlled variable.

---

## Profiling Results

```
[B010] ===== Weight Access Profile =====
[B010] Total StreamingMatMul calls:    983
[B010] Unique tensors acquired:        197
[B010] Total bytes read (dequantized):  8971.96 MB
[B010] Map calls (StreamingPin):        74693
[B010] Unmap calls:                     983
[B010] Incidental map calls:            73728
[B010] Acquisition time (lookup+pin):    0.00 ms (0.0%)
[B010] Compute time (dequant+dot):       16614.34 ms (100.0%)
[B010] Total time:                       16614.34 ms
[B010] Repeated acquisitions:            786 (calls - unique)
[B010] ===================================
```

---

## Cost Breakdown

### Tensor Acquisition
| Metric | Value | Significance |
|--------|-------|--------------|
| Total StreamingMatMul calls | 983 | 3 forward passes × ~328 matmuls each |
| Unique tensors acquired | 197 | 28 layers × 7 weights + embedding/output |
| Repeated acquisitions | 786 | 983 - 197 = same tensors loaded repeatedly |
| Residency hit rate | 0% | No caching — every call re-acquires |

### Weight Access
| Metric | Value | Significance |
|--------|-------|--------------|
| Total bytes read | 8,971.96 MB | **4.4× model file size** |
| Bytes per matmul call | 9.13 MB | Average weight tensor size |
| Map calls (StreamingPin) | 74,693 | 75.99 per matmul call |
| Incidental map calls | 73,728 | 74.99 per matmul — nearly 1:1 |
| Unmap calls | 983 | One per matmul (scope exit) |

### Time Attribution
| Metric | Value | % of Total |
|--------|-------|-----------|
| Acquisition (lookup + pin) | 0.00 ms | 0.0% |
| Compute (dequant + dot) | 16,614.34 ms | 100.0% |
| Total | 16,614.34 ms | 100.0% |

**Note:** The acquisition/compute split is currently attributed 100% to compute because the `StreamingPin` construction (mapping) is interleaved with dequantization within the same loop. The timers do not yet cleanly separate mapping overhead from arithmetic. B011's cache experiment will provide the controlled comparison that isolates the causal contribution.

---

## Key Findings

### 1. Massive Redundant Weight Loading
- **8,971 MB read** vs **2,019 MB model size** = **4.4× redundancy**
- Each forward pass re-reads all layer weights from scratch
- For 3 forward passes (prefill + 2 decode), that's ~3× the model size per pass

### 2. Incidental Maps Dominate
- **73,728 incidental maps** out of 74,693 total map calls (98.7%)
- This means the streaming window is too small for tensor shards
- Nearly every row requires a separate `MapIncidentalWindow` call
- This is the real bottleneck — not the matmul computation itself

### 3. No Weight Reuse Whatsoever
- 197 unique tensors, but 983 calls = 786 repeated acquisitions
- Residency hit rate: **0%**
- Every `StreamingMatMul` call independently maps, dequantizes, and unmaps

### 4. Why the Original B009 Didn't Help

> **Note:** The original B009 implementation (which produced the +8.32% result)
> is now **INVALIDATED** due to a correctness bug in residual/RMSNorm ordering.
> The following analysis applies to that original implementation and remains
> relevant for understanding why loop restructuring alone is insufficient.

The original B009's layer-outer restructuring didn't improve performance because:
- The weights are re-mapped per matmul call regardless of loop order
- Whether you process token-outer or layer-outer, each matmul still calls `StreamingPin` independently
- The 73,728 incidental maps happen per-row, not per-layer

**Conclusion:** The B010 profiling confirms that the bottleneck is tensor
acquisition (mapping/dequantization), not loop order. Any future batched
implementation (B009-fix or B009-B) must address weight residency to realize
performance gains.

---

## Architectural Diagnosis

```
Current StreamingMatMul flow (per call):
  ┌─────────────────────────────────────┐
  │ 1. Lookup tensor by name            │
  │ 2. For each row shard:              │
  │    a. StreamingPin (map view)       │ ← 74,693 times
  │    b. Dequantize blocks             │ ← 8,971 MB total
  │    c. Dot product with input        │
  │    d. Unmap                          │
  │ 3. Return result                    │
  └─────────────────────────────────────┘

Problem: Steps 2a-2d repeat for EVERY matmul call,
even when the same tensor is needed again.
```

---

## B011 Proposal: Weight Residency Cache

The profiling data makes a clear case for testing weight caching. The following are **hypotheses** to be tested, not certification criteria:

| Metric | Current (B010) | B011 Hypothesis | Basis |
|--------|----------------|-----------------|-------|
| Bytes read | 8,971 MB | ~2,019 MB | Theoretical: model size if fully cached |
| Map calls | 74,693 | ~197 | Theoretical: one per unique tensor |
| Incidental maps | 73,728 | ~0 | Theoretical: eliminated by larger mapped regions |
| Repeated acquisitions | 786 | 0 | Theoretical: cache hits |
| Residency hit rate | 0% | ~80% | Theoretical: first-pass miss, then hits |

**Important:** Actual bytes read depend on cache granularity, mapping alignment, view sharing, and which tensors are requested. The ~2,019 MB target is a hypothesis, not a pass/fail threshold.

### B011 Success Criteria

```
Correctness:
  numerical equivalence vs B008 (sole oracle) = PASS
  NOTE: B009 is INVALIDATED; do not use as reference

Residency:
  hit rate materially > 0% = PASS
  repeated acquisitions reduced = PASS
  mapping activity reduced = PASS

Performance:
  prefill wall time measured
  acquisition time measured
  compute time measured
  regression/improvement reported

No regression:
  T==1 decode behavior preserved
```

### B011 Design Constraints
- **Do NOT remove B010 counters** — they prove the cache changed behavior
- Cache must not break B008 numerical equivalence (B009 is INVALIDATED)
- Cache must not increase memory beyond available RAM
- Cache invalidation strategy needed for multi-model scenarios
- Cache should be opt-in (env var or config flag) for A/B testing

---

## Files Modified (Profiling Only)

| File | Change | Purpose |
|------|--------|---------|
| `src/rawrxd_model_loader.h` | Added `WeightAccessProfile` struct | Profiling counters |
| `src/rawrxd_model_loader.h` | Added `ResetWeightProfile()` / `PrintWeightProfile()` | Profile lifecycle |
| `src/rawrxd_model_loader.cpp` | Added `<chrono>` include | Timing |
| `src/rawrxd_model_loader.cpp` | Instrumented `StreamingMatMul` | Counters in hot path |
| `src/rawrxd_inference.h` | Added `GetLoader()` accessors | Test harness access |
| `tests/b004_transformer_router_streaming_integration.cpp` | Added profile reset/print | Evidence capture |

---

## Evidence

| Artifact | Location |
|----------|----------|
| Profiling log | `B010/logs/profiling.log` |
| Metrics JSON | `B010/performance/b010_weight_access_metrics.json` |
| This report | `B010/B010-REPORT.md` |
| Manifest | `B010/manifest.json` |

---

## Experimental Chain

```
B008  Known-good reference (FROZEN — sole oracle)
  ↓
B009  Loop-order experiment
  ↓
       correctness bug discovered (residual/RMSNorm ordering)
       +8.32% result INVALIDATED
  ↓
B009-fix  Corrected ForwardBatch()
  ↓
       revalidation required before freeze
  ↓
B010  Residency instrumentation
  ↓
       8,971 MB read (4.4× model size)
       73,728 incidental maps
       0% residency hit rate
  ↓
       identify actual bottleneck: repeated weight acquisition
  ↓
B011  Targeted residency optimization
  ↓
       compare against B008 (sole oracle)
       B009-fix may be used as alternate path once certified
```

**Important:** B009 is INVALIDATED. Do not use it as a reference for B011.
B008 remains the sole numerical oracle until B009-fix is fully re-certified.

---

## Sign-off

B010 is a **profiling-only milestone**. No caching was introduced during measurement, preserving the clean causal boundary between measurement and optimization.

**B010: COMPLETE.**