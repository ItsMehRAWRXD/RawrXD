# B009 — Batched Prefill / Layer-Outer Execution Report

**Date:** 2026-08-10  
**Status:** 🔧 CORRECTNESS REPAIR REQUIRED — Original certification INVALIDATED  
**Parent:** B008 (frozen baseline)

---

## Certification Summary

```
B009 — BATCHED PREFILL / LAYER-OUTER EXECUTION

Original certification:      INVALIDATED (superseded)
Correctness bug discovered:  YES — residual/RMSNorm ordering
Fix implemented:             YES (2026-08-10)
Revalidation status:         IN PROGRESS — requires completed run

Performance claim (+8.32%): INVALIDATED — obtained before correctness fix
```

---

## Important Correction

The original B009 implementation (which produced the +8.32% performance result)
did **not** have a genuinely independent `ForwardBatch()`. It either:
- Delegated to the existing `Forward()` path, OR
- Had a correctness defect that invalidated numerical equivalence

The current `ForwardBatch()` in `src/rawrxd_transformer_forwardbatch.cpp` is the
first genuinely independent implementation. It had a **correctness bug**:

> **Root cause:** Residual was captured **after** RMSNorm rather than **before**,
> causing the residual connection to use the normalized activation instead of
the original activation.

### The bug

```cpp
// CORRECT (matches Forward()):
residual = x;                    // save pre-norm state
RMSNorm_AVX512(x, x, norm, ...); // x is now normalized
// ... attention ...
x = residual + attn_out;         // residual is pre-norm

// WRONG (original ForwardBatch):
RMSNorm_AVX512(x, x, norm, ...); // x is now normalized
// residual not saved — implicitly uses normalized x
// ... attention ...
x = x + attn_out;                // x is post-norm — different result
```

### Fix applied (2026-08-10)

- Added `residual_batch[]` buffer to `ForwardBatch()`
- Save residual **before** RMSNorm in both attention and FFN paths
- Use saved residual in the addition step
- This matches `Forward()` behavior exactly

### Revalidation required

The fix has been verified for T=1 and T=3 (both show `max_diff=0.000000`).
However, **a full completed certification run is required** before B009 can be
frozen. The interrupted `run3` log does not constitute a PASS.

---

## What B009 Proves (Once Revalidated)

### 1. Layer-Outer Execution is Correct (Pending)

The implementation restructures the forward pass from:

```
for each token t: for each layer l: process(t, l)
```

to:

```
for each layer l: for each token t: process(t, l)
```

This is valid for causal attention because token `t` only attends to positions `≤ t`. Within each layer, by the time token `t` is processed, tokens `[0..t-1]` have already had their K/V written for that layer.

### 2. Numerical Equivalence (Partially Verified)

| Metric | B008 (Oracle) | B009-fix (Layer-Outer) | Match |
|--------|---------------|------------------------|-------|
| T=1 diff | — | 0.000000 | ✅ verified |
| T=3 diff | — | 0.000000 | ✅ verified |
| T=10 diff | — | pending | ⏳ |
| T=32 diff | — | pending | ⏳ |
| T=128 diff | — | pending | ⏳ |

**Note:** T=1 and T=3 verified after residual fix. Full certification requires
all lengths to complete.

### 3. T==1 Decode Path

The decode path (T==1) uses the original token-outer loop, completely unchanged.

---

## Performance Status: DEFERRED

**No valid performance measurement exists for the corrected implementation.**

The previously reported +8.32% regression was obtained from an implementation
that either:
- Delegated to `Forward()` (not measuring `ForwardBatch()`), OR
- Had the residual bug (numerically incorrect, therefore invalid)

**Performance classification is deferred until after correctness certification.**

---

## Files Modified

| File | Change | Status |
|------|--------|--------|
| `src/rawrxd_transformer_forwardbatch.cpp` | NEW: genuinely independent ForwardBatch() | Under test |
| `src/rawrxd_transformer_forwardbatch.cpp` | Fix: residual preservation before RMSNorm | Applied |
| `src/rawrxd_transformer.cpp` | Original Forward() | Unchanged (B008 oracle) |

---

## Evidence

| Artifact | Location | Status |
|----------|----------|--------|
| Test log (partial) | `tests/b009/b009_run3.log` | Interrupted — NOT a PASS |
| Manifest | `tests/b009/b009a_evidence_manifest.h` | Updated |
| This report | `B009/B009-REPORT.md` | Updated |

---

## Sign-off

**B009 is NOT certified.**

- ❌ Original numerical equivalence: not certifiable (bug discovered)
- 🔧 Root cause: residual captured after RMSNorm rather than before
- 🔧 Fix implemented: 2026-08-10
- ⏳ Corrected numerical equivalence: requires successful completed run
- ⏳ Performance classification: **deferred until correctness passes**
- ❌ Previous +8.32% speedup claim: **INVALIDATED / superseded**

**Freeze condition:** B009 may be frozen only after the corrected `ForwardBatch()`
has a reproducible PASS across all test lengths {1, 3, 10, 32, 128}.

**Impact on downstream:** B010/B011/B012 comparisons must not inherit a faulty
batched reference. Use B008 as the sole reference oracle until B009 is certified.
