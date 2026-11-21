# Four-way policy matrix (G07) — partial, 2026-11-21

Sprint gate: **tracking and retention are independent controls**

## Runs (tinyllama-1.1b-chat Q4_K_M, dense, 8 prefill / 8 generate, GPU)

| Case | Flags | VRAM hits | hit rate | evictions | Expert ledger |
|---|---|---|---|---|---|
| T1_R0 | `--strata` | 2,326 | 0.9375 | 0 | observations=0 (dense) |
| T0_R1 | `--strata-retain-weights` | 1 | 0.0004 | 2,479 | not printed |
| T0_R0 | neither | 1 | 0.0004 | 2,479 | not printed |
| T1_R1 | both | 1 | 0.0004 | 2,479 | not printed |

## Why this matrix is not yet conclusive

The chosen model is **dense**, so it has **no MoE block transitions** and therefore does not
exercise `TrimUnpinnedWeightCache()` as the dominant path. Results are inconsistent with the
MoE behaviour (T1_R0 shows 0 evictions; T0_R1 shows 2,479), which means the dense path is
governed by a different trim site than the one under test.

**The four-way matrix must be run on `deepseek-coder-v2_16b.gguf`** (27 blocks, MoE) to be
meaningful. At ~2 min per run that is ~8 min for all four cases — one full sprint.

## What is already established on the MoE model

| Case | Result |
|---|---|
| tracking ON, retention OFF | flush: 0 hits, 28,991 evictions (`1591a838a3` baseline) |
| tracking ON, retention ON | 25,220 hits, 0 evictions, 0.8699, 6.52 GiB (`a449bc13e7`) |
| retention ON, tracking OFF | **not yet measured on MoE** |
| neither | baseline flush (bench default) |

So two of four cells are proven; the other two require MoE runs.

## Non-claims

G07 is **not closed**. Independence of the two controls is strongly suggested by the code
(separate flags, separate code paths) but not yet demonstrated by a full matrix on the
architecture where retention matters.

## Next

1. Run the four cells on `deepseek-coder-v2_16b.gguf` with `--prefill 32 --generate 16`.
2. Require: tracking changes only the ledger; retention changes only the trim.
3. Then G12 (non-Strata regression on the current exe) and G13 (same-process transitions).