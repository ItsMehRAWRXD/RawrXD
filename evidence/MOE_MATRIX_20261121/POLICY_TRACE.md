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