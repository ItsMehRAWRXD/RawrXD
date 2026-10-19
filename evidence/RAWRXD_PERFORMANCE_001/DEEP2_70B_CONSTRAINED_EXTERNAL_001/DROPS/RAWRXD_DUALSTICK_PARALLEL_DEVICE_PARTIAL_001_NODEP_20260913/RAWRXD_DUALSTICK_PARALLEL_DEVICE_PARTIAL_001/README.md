# DualStick Parallel + Device Partial 001

Base: `DUALSTICK_REUSE_MICROFIX_001=PASS`, seal `9c4213e679`.

This source-only C++17 drop owns the next post-reuse gate:

- two independent stick worklists execute concurrently;
- each expert produces Down into a device-resident path contract;
- route weight is accumulated into one device partial per stick;
- host receives at most one H-vector per used stick per MoE layer;
- host performs exactly one final `p0 + p1` join;
- worker failure aborts the layer and performs no partial host accumulation;
- mock/selftest backend cannot mint product authority.

## Standalone verification

The included selftest proves orchestration and fail-closed semantics with no third-party dependencies. It does **not** prove Vulkan product execution.

Expected output includes:

```
TRUE_PARALLEL_STICKS=PASS max_concurrent=2
DEVICE_PARTIAL_D2H_2VEC=PASS d2h=2 down=8 accum=8
MOCK_AUTHORITY_BLOCK=PASS
WORKER_FAIL_CLOSED=PASS
DSDP_SELFTEST=PASS
TPS_PERFORMANCE_AUTHORITY=0
TARGET_35_50_TPS=UNMINTED
PROMOTE=0
```

## Product integration rule

Do not wire the concurrency block directly around current RawrXD globals. The base seal still contains non-atomic `MoEPlaceLiveCounters`, bundle residency metadata, and DualStick residency accounting. Follow `rawrxd_bind/README_BIND.md`: worker-private counters + merge, protected first-touch metadata, and no global lock around hit-only GPU execution.

For the device path, the current RawrXD `VulkanCompute::DeviceBuf`/`DispatchGemvQuant`/`DispatchSwiGLU` APIs are the correct substrate. The missing acceptance-critical primitive is weighted device accumulation (or a fused Down epilogue) together with pinned-weight lookup on the device-buffer GEMV path. Until that live backend attests, the gate stays HOLD.
