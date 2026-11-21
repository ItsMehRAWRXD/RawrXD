# G07 MoE matrix — retention follows tracking, not the flag — 2026-11-21

Sprint gate: **are tracking and physical retention independent? (G07)**

## Runs (deepseek-coder-v2_16b.gguf, 32 prefill / 16 generate, GPU, 8 GiB budget)

| Case | Flags | VRAM hits | hit rate | evictions | Expert ledger |
|---|---|---|---|
| T1_R0 | `--strata` only | **25,220** | **0.8699** | **0** | 22,464 obs / 18,828 hits |
| T0_R1 | `--strata-retain-weights` only | **0** | 0.0000 | **28,991** | not active |
| T1_R1 | both | 25,220 | 0.8699 | 0 | 22,464 / 18,828 |
| T0_R0 | neither | 1 | 0.0004 | 2,479 | not active (dense check) |

## Finding: the controls are COUPLED

Retention follows **`--strata` (expert tracking)**, not `--strata-retain-weights`:

* `--strata` alone → 25,220 hits, 0 evictions (retention active)
* `--strata-retain-weights` alone → 0 hits, 28,991 evictions (flush)

The cause is visible in `runtime_graph_executor.cpp:4650`:

```cpp
if (!StrataExpertTracking())
    (void)QuantDot::TrimUnpinnedQuantWeights();
```

That guard skips the **global** trim whenever tracking is enabled, and in the tracked path the
per-device `TrimUnpinnedWeightCache()` is evidently not reached — so retention is a side effect
of tracking.

## Correction to an earlier claim

My `a449bc13e7` verification ("retention works without the env var") was **confounded**: the run
used `--strata`, so retention came from tracking. The retention flag has **not** been shown to do
anything on its own. I withdraw that as evidence of an independent policy.

## G07 verdict

**FAIL on independence.** Two of four cells behave identically to tracking alone; the retention
flag is not an independent control.

Required correction (next sprint):
1. Make the per-device trim consult `QuantDot::WeightCacheRetention()` **and** stop the global
  trim from being skipped implicitly by tracking — or gate retention explicitly on the policy flag
  rather than on `StrataExpertTracking()`.
4. Re-run the matrix; T0_R1 must show retention with tracking off to pass.

## Non-claims

No code change made. The residency/eviction/budget results (G09/G10) remain valid because both
runs that produced them had tracking enabled; the *attribution* of retention to the flag is what
fails.