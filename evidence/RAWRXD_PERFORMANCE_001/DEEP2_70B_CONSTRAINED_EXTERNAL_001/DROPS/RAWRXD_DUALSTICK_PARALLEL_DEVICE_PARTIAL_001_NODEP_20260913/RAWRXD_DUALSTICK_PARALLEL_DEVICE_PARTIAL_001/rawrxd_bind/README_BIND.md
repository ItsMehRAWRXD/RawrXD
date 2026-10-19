# RawrXD bind notes — base 9c4213e679

The live base has two independent blockers this drop is designed to close without reopening the reuse seal:

1. `K2NativeMoEFfn_Place.cpp` builds `ix0`/`ix1`, then executes stick 0 followed by stick 1. That is batching, not concurrency.
2. `K2NativeMoEFfn_ExpertGpu.cpp` uses host-I/O `DispatchGEMVQuant` for Gate, Up and Down, so the routed expert output is returned to host before stick-local weighting.

## Integration order

### A. Race-safe true parallel worklists

- Add one worker per non-empty stick list.
- Give each worker a private counter block; merge after join. Do **not** increment the current plain `MoEPlaceLiveCounters` concurrently.
- Defer `MoEPlaceGlobal().MarkHot()` until the main thread after both workers join, or protect it with an explicit lock.
- Protect `DualStickExpertBundle` and `DualStickStreamWindow_Vc` residency tables during first-touch misses. Hit-only execution must not take a global serialization lock around GPU work.
- Timestamp each worker begin/end and compute intersection: `overlap=max(0,min(end0,end1)-max(begin0,begin1))`.

### B. Device Gate/Up/SwiGLU/Down

Use the existing `VulkanCompute::DeviceBuf` API, `EnsureForwardArena`, `UploadBuf`, `DispatchGemvQuant`, `DispatchSwiGLU`, and `DownloadBuf` to keep the intermediate activation path on the stick device. Do not claim hit-residency until the device-buffer quant dispatch can bind the existing pinned weight by key; if that API cannot consume a pin key, extend it rather than re-uploading packed weights.

Required backend shape:

```
hidden(host once/stick/layer)
  -> ArenaHidden(device)
Gate pin -> ArenaGate
Up   pin -> ArenaUp
DispatchSwiGLU(ArenaGate,ArenaUp,ArenaFFNAct)
Down pin -> ArenaDown
weighted_accumulate(ArenaDown, stickPartial, routeWeight)
... next expert ...
DownloadBuf(stickPartial) exactly once/stick/layer
host join p0+p1 exactly once
```

### C. Weighted device accumulate primitive

Do not fake this with per-expert `DownloadBuf`. Add/attest a tiny device primitive equivalent to:

```
partial[i] += weight * down[i]
```

It may be a dedicated Vulkan compute pipeline or a fused epilogue on Down. The acceptance counter is `HOST_EXPERT_DOWN_VECTORS=0`; if that counter is non-zero, DEVICE_PARTIAL is HOLD.

## Fail-closed requirements

A worker failure must join the peer worker, abort both device partials, perform no final host accumulation, and emit a failure receipt. `selected==executed` remains mandatory. Standalone tests cannot set `PRODUCT_BACKEND_ATTESTED=1`.
