# Phase 1D — residency budget through the session — 2026-11-21

Sprint gate: **evictions must be budget-driven, not capacity accidents**

## Setup

```
exe   F:\rawrxd\build\Release\deep2_strata_chat_session.exe
SHA256 5D9F57467529BF443DC044D0D3E525C93D53489423B9525019C18A72F2D3890E
model deepseek-coder-v2_16b.gguf (deepseek2 MoE)
cmd   --tokens 1 450 4996 --max-new 16 --gpu --strata --weight-cache-budget 1073741824
```

## Observed

```
[tok 0..15] streamed (16 tokens)
DISPATCH gpu_calls=11476 cpu_calls=0 nonfinite=0
EXPERT_LEDGER observations=8892 hits=6096 evictions=0
SESSION_STATUS OK
EXIT=0
```

Expert hit rate = 6,096 / 8,892 = **0.6856** (up from 0.5496 at 8 tokens).

## Assessment

| Gate | Result |
|---|---|
| Session runs on MoE with a budget flag | PASS |
| GPU dispatches | 11,476 |
| CPU calls | 0 |
| Non-finite logits | 0 |
| Expert observations | 8,892 |
| Expert hits | 6,096 |
| **Budget-driven evictions** | **0 — NOT OBSERVED** |
| Exit | 0 |

**The eviction gate is not satisfied.** With a 1 GiB budget and a 16B MoE, evictions stayed
at zero and the hit rate improved, which means the expert working set fits inside the
configured budget for this workload — i.e. the cache is not being forced into eviction.

## Two possibilities to separate next

1. **The budget is not reaching the cache.** The driver has no confirmation print (the bench
  prints `WEIGHT_CACHE_BUDGET <bytes>`; my session does not). Until that line is added, budget
  propagation is unproven.
2. **The workload is too small to thrash.** 3 prefill + 16 decode tokens may simply not cycle
  enough distinct experts to evict, even at 1 GiB.

## Recommended next

1. Add the same confirmation print to `StrataChatSession::Open`
  (`[STRATA_WEIGHT_CACHE_BUDGET] bytes=...`) so propagation is provable.
2. Then force pressure: `--weight-cache-budget 268435456` (256 MiB) with a longer generation
  (`--max-new 48`). Expect `evictions > 0` and live bytes ≤ budget.
3. Distinguish expert-cache bytes from total VRAM (weights, KV, scratch) when reporting.

## Non-claims

No eviction behaviour was demonstrated. The session's residency *reuse* is proven
(hits > 0, observations > 0), but the budget-driven eviction path is not.