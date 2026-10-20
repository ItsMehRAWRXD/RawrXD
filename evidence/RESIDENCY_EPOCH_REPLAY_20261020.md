# Deep2 Residency Epoch + Deferred Dispatch Replay

Date: 2026-10-20

## Scope

This slice extends the asynchronous weight streamer with an allocation epoch
and a deferred GPU-dispatch lease.  It also adds a deterministic, CPU-only
expert residency planner and LRU replay simulator.

## Source changes

- `src/deep2/VulkanWeightStreamer.hpp/.cpp`
  - Allocation epochs are carried by transfer tickets and resident bindings.
  - Recycled slots cannot satisfy an old ticket or binding.
  - `ready()` is a non-blocking dependency query.
  - Concurrent waiters coalesce on one backend wait through a condition
    variable; a completed dependency is never waited a second time.
  - `acquireForDispatch()` pins a ready allocation with a lease.
  - `releaseAfterGpuCompletion()` retires the lease; ordinary release is
    denied while a dispatch lease is live.
- `src/deep2/ResidencyReplay.hpp`
  - Weighted expert candidate planner with bounded lookahead and byte budget.
  - Deterministic trace recorder.
  - CPU-only LRU residency replay with transfer, hit, eviction, and rejection
    counters.
- `tests/deep2_weight_streamer_test.cpp`
  - Covers non-blocking readiness, lease pinning, epoch invalidation, planner
    ranking, replay determinism, and repeated-consumer wait behavior.

## Verification

```text
cmake --build build_streamer_contract --config Release --target deep2_weight_streamer_test --parallel 2
ctest --test-dir build_streamer_contract -C Release -R deep2_weight_streamer_contract --output-on-failure
cmake --build build --config Release --target deep2_engine_lib --parallel 2
```

Results:

- Contract test: `1/1 passed`.
- `deep2_engine_lib`: Release library built successfully.
- The synthetic replay exercised 4 requests, 3 transfers, 1 cache hit, and 2
  evictions with `status=PASS`.

## Certification boundary

`SOURCE_WIRED=1` and the CPU contract test reached are established.  This is
not a live GPU transfer or throughput receipt.  No Vulkan benchmark was
launched, the RX 7800 XT remains unavailable under Code 43, and no dual-GPU
execution or 150 TPS performance claim is made.

`NOT_RUN != PASS`.
