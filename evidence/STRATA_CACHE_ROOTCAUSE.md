# Root cause: block-boundary weight-cache flush — 2026-11-21

Sprint gate: **why 28,991 evictions and 0 hits under an 8 GiB budget**

## The call site

`src/deep2/vulkan_compute.cpp:3812`

```cpp
bool VulkanCompute::TrimUnpinnedWeightCache(uint32_t completedBlock) {
    if (!device_) return false;
    // All Deep2 quant-dot submissions are fence-waited before their outputs
    // are consumed. Waiting here makes destruction safe ...
    if (vkDeviceWaitIdle(device_) != VK_SUCCESS) return false;
    UnpinAllWeights();
    const size_t beforeBytes = weightCacheBytes_;
    const size_t beforeEntries = weightCache_.size();
    const size_t beforeResidentBytes = residentObjectBytes_;
    clearWeightCache();          // <-- unconditional full flush
    ...
}
```

Called at **every MoE block transition**. `clearWeightCache()` drops the entire
weight cache each time, so no slice can survive to be reused.

## Why this explains every observation

| Observation | Explanation |
|---|---|
| `hits = 0` | Nothing survives a block boundary to be hit |
| `misses = evictions + 1` (28,992 = 28,991 + 1) | Each miss inserts one entry; the next block flush evicts it |
| `device_bytes_live = 172,450,336` (164 MiB) under an 8 GiB budget | The cache never accumulates beyond a single block's slice |
| Budget changes have no effect | Capacity never binds; the flush is unconditional |
| Expert ledger shows 41,121 observations | The ledger observes residency decisions; the weight cache is flushed independently |

## Correction to earlier interpretation

The executor-level guard added previously

```cpp
if (!StrataExpertTracking())
    (void)QuantDot::TrimUnpinnedQuantWeights();
```

skips the **global** trim, but `VulkanCompute::TrimUnpinnedWeightCache` is a
**separate, per-device path** that still runs unconditionally. That is why the
earlier "trim eliminated" conclusion did not change the counters.

## The minimal correct change (next sprint)

Preserve the function's safety role while retaining resident slices:

1. Keep `vkDeviceWaitIdle(device_)` and `UnpinAllWeights()` — they are what make
  destruction safe for in-flight work.
2. Under Strata expert tracking, **do not** `clearWeightCache()`; instead evict
  only entries that are not pinned/resident, so reused slices survive.
3. Leave non-Strata behaviour byte-identical.

## Acceptance for the fix

- `WEIGHT_CACHE_EVICTIONS`: budget-driven only (0 when nothing is pinned out)
- `S02_VRAM_CACHE hits > 0`, `hit_rate` materially above 0
- `device_bytes_live` grows toward the configured budget (not pinned at 164 MiB)
- `total_evictions == budget_evictions + trim_evictions` with `trim_evictions` limited
  to genuine unpinned reclamation
- Non-Strata control run unchanged
- `nonfinite_logits = 0`, `cpu_calls = 0`, clean shutdown

## Non-claims

No code change made. The flush is identified as the mechanism; the fix is not yet
implemented or verified.