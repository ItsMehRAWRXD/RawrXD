# Eviction attribution — budget is zero, LRU is not the evictor — 2026-11-21

Sprint gate: **attribute the 28,991 evictions to their actual execution path**

## Witness

```
[TRIM_STATE] budget=0 bytes=0 entries=0 resident=0 policy=1
S02_VRAM_CACHE hits=1 misses=930 evictions=929 hit_rate=0.0011
device_bytes_live=53951480
(no [LRU_EVICT] lines at all)
```

## Findings

1. **The device-level budget is `0`.** `weightBudgetBytes_ == 0` means
  `evictWeightCacheUntil()` cannot evict anything — its loop is guarded by
  `while (weightBudgetBytes_ && ...)`. So the configured 8 GiB global budget is **not**
  reaching this device instance.
2. **The LRU path is not the evictor.** No `[LRU_EVICT]` line was emitted, and the
  eviction counter still advanced by 929.
3. Therefore a **third path** removes entries — consistent with `misses = evictions + 1`
  and with a single-entry residency plateau: each insert appears to replace the previous
  entry rather than accumulate.

## Consequences

* The "capacity" hypothesis is dead: the device has no budget limit set, yet residency stays
  at ~54 MB (dense) / 164 MiB (MoE).
* The "budget not propagating" issue is real but separate: `SetWeightCacheBudget()` sets a
  global that is applied at first init; here it did not reach `weightBudgetBytes_`.
* The primary defect is the **insert/evict path**, not the budget and not the trim.

## Next (one sprint)

1. Find the insertion function (where `weightCache_` entries are created) and any
  entry-count or residency cap applied there.
2. Log `weightCache_.size()` before/after each insert for the first few inserts.
3. Confirm whether an unconditional `evict` / `clear` on insert exists.
5. Separately fix budget propagation: `vk->SetQuantWeightBudgetBytes()` at init.

## Non-claims

No fix made. The earlier RCU-guard experiment was reverted; the tree is at the
policy-decoupled state (`b7a79ddb83`) plus diagnostics.