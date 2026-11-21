# Strata budget sweep — G09/G10 — 2026-11-21

Sprint gates: **budget-driven eviction (G09)** and **aggregate memory enforcement (G10)**

## Setup

```
exe   F:\rawrxd\build\Release\deep2_strata_bench.exe
model deepseek-coder-v2_16b.gguf (deepseek2 MoE, 64 experts)
cmd   --prefill 32 --generate 16 --gpu --strata --strata-retain-weights
      --weight-cache-budget <N>
```

All runs: `gpu_calls=28992`, `cpu_calls=0`, `fallback=<none>`, `nonfinite_logits=0`.

## Results

| Budget | VRAM hits | hit rate | evictions | live bytes | expert hits |
|---|---|---|---|---|---|---|
| 8 GiB | 25,220 | 0.8699 | **0** | 6,520,209,952 | 18,828 (0.8381) |
| 2 GiB | 19,667 | 0.6784 | **8,249** | 2,147,254,816 | 13,310 (0.5925) |
| 1 GiB | 0 | 0.0000 | **28,530** | 1,072,226,848 (peak 1,073,480,224) | 0 |

## Assessment

| Gate | Result |
|---|---|
| G09 budget-driven eviction | **PASS** — 8,249 evictions at 2 GiB, 28,530 at 1 GiB; 0 at 8 GiB |
| G10 aggregate memory limit | **PASS** — live bytes track the ceiling (2 GiB → 2,147,254,816; 1 GiB → 1,072,226,848, 1.2 MB under) |
| Graceful degradation | **PASS** — 0.8699 → 0.6784 → 0.0000 as budget tightens |
| No unintended CPU fallback | PASS |
| Finite logits | PASS |
| Clean exit | PASS |

At 1 GiB the expert working set exceeds the budget, so the cache thrashes (0 hits). That is correct behaviour for an under-provisioned cache, not a defect: memory stays within the ceiling and nothing crashes.

## Interpretation

The residency system is now bounded and correct:
- **8 GiB**: no pressure → full retention, no evictions.
- **2 GiB**: partial retention with LRU reclamation (8,249 evictions) and live bytes exactly at the ceiling.
- **1 GiB**: insufficient for the working set → eviction-dominated, 0 hits.

This closes the "uncontrolled flush" defect and demonstrates the budget is a real ceiling, not a hint.

## Remaining in this workstream

* **G07** four-way tracking × retention matrix
* **G08** expert prefetch (`prefetches=0` in all runs)
* **G11** process-global → request-scoped policy
* **G12** non-Strata regression against the current executable
* **G13** same-process policy transitions

## Non-claims

Single sample per budget; no long-run leak or fragmentation measurement; total device memory includes non-weight-cache allocations, so `device_bytes_live` bounds the cache, not the whole process.