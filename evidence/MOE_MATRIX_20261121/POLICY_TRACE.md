# Policy propagation verified; the remaining flush is the global trim — 2026-11-21

Sprint gate: **trace one boolean from CLI to the cache-clearing decision**

## Witness

```
[POLICY_SET] value=1 addr=00007FF729CFFF48
[POLICY_GET] value=1 addr=00007FF729CFFF48   (x9, same address)
```

The retention flag reaches the trim boundary as **true**, at a stable address, on every read.
So there is **no symbol mismatch, no duplicate storage and no reset** — policy propagation works.

## Therefore the remaining flush comes from another clear path

`vulkan_compute.cpp:3830` (device trim) is now correctly guarded:

```cpp
if (!(::RawrXD::Deep2::QuantDot::WeightCacheRetention()))
    clearWeightCache();
```

but `runtime_graph_executor.cpp:4650` **always** calls the *global* trim:

```cpp
(void)QuantDot::TrimUnpinnedQuantWeights();
```

That global trim was previously skipped when expert tracking was on — which is why the coupled build retained. My decoupling made it unconditional, so it now flushes regardless of the policy.

## The correct fix (next sprint, 2 lines)

Gate the **global** trim on the same explicit policy instead of on tracking:

```cpp
if (!::RawrXD::Deep2::QuantDot::WeightCacheRetention())
    (void)QuantDot::TrimUnpinnedQuantWeights();
```

with the device-level trim still always running for `vkDeviceWaitIdle` / `UnpinAllWeights` and
skipping only `clearWeightCache()`.

That makes all four cells correct:
- retention OFF → global trim flushes (T0_R0, T1_R0)
- retention ON → global trim skipped, device trim keeps contents (T0_R1, T1_R1)
- tracking affects only the expert ledger

## Evidence this sprint

- Policy value = 1 at the trim boundary (address stable) → propagation PASS
- T1_R0 (tracking only) flushes → tracking no longer forces retention (G07 half-fix confirmed)
- Remaining flush attributable to the unconditional global trim, not to the flag path

## Non-claims

The four-way matrix is not yet green; T0_R1 still flushes. No code change committed this sprint beyond the earlier decoupling (`b7a79ddb83`).
## Addendum: the global trim is a pure forwarder

`quant_dot_dispatch.cpp`:

```cpp
size_t TrimUnpinnedQuantWeights() {
    return (g_active_device >= 0 ? GpuFor(g_active_device) : Gpu())
        .TrimUnpinnedQuantWeights();
}
```

No synchronization, reclamation or budget logic of its own � it calls the device function, which
already gates `clearWeightCache()` on `QuantDot::WeightCacheRetention()`.

Therefore gating the global trim would change nothing: in T0_R1 the policy getter returns **1** at
the trim, so `clearWeightCache()` is already skipped, yet 28,991 evictions still occur.

## Remaining suspect: the RCU / direct-resident reclamation

Inside `TrimUnpinnedWeightCache`, after the policy-gated clear, the function continues:

```cpp
// The direct-resident/RCU path is a second owner of streamed weights and
// is not represented by weightCache_. ... its published views can be
// invalidated and reclaimed here as well.
```

That second reclamation path runs unconditionally and is the most likely source of the residual
evictions with retention enabled. Next step: make that reclamation policy-aware too, or confirm
it is mandatory for pointer-lifetime safety and exclude it from the eviction counters.
