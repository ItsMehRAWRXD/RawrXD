# RawrXD K2 live binding contract

This document maps `EnterpriseDualStickLocality` onto the K2-native routed-expert seam without changing K2 router semantics.

## Existing live seam to replace

The branch path in `src/deep2/K2NativeMoEFfn_Expert.cpp` currently obtains:

```text
GetExpertGate / GetExpertUp / GetExpertDown
→ ReadExpertSlice into fresh gateBuf/upBuf/downBuf vectors
→ K2MoEExecExpertGpu(... host pointers ...)
```

and `K2NativeMoEFfn_ExpertGpu.cpp` performs DualStick acquire calls but then dispatches quant GEMV using those host-buffer pointers.

The production bind must move bundle ownership/residency above that per-expert temporary-buffer path.

## 1. Engine lifetime

Own exactly one `EnterpriseDualStickLocality` instance per loaded K2 model/session residency domain, not per expert or layer.

Initialize it after K2 tensor index + GPU devices are ready. Clear/destroy it before device teardown or model unmap.

## 2. Loader callback

`LoaderOps::LoadBundle` is the only host-load seam.

For `(layer, expert)`:

1. Resolve Gate/Up/Down with the existing `GlobalTensorIndex::FindExpertSlice` authority.
2. Treat returned physical offset/size as authoritative.
3. Validate but do not override physical expert geometry using guessed tensor math.
4. Read/copy each physical slice into `LoadedExpertBundle::{gate,up,down}.bytes` once per host-staging miss.
5. Fill the exact GGML type for each role.
6. Fill hidden/intermediate dimensions from the tensor geometry already validated by K2 MoE execution.

Do **not** construct fresh Gate/Up/Down vectors in `K2NativeMoEFfn_Expert.cpp` after this bind.

## 3. Router/placer handoff

K2 router remains authoritative:

```text
sigmoid(W@h)
choice = score + eScoreCorrectionBias
noaux_tc top-k(choice)
weights = unbiased score[selected IDs]
normalize
× routed_scaling_factor 2.827
```

Convert the already-selected result into `RoutedExpert[]`:

```cpp
RoutedExpert r;
r.expertId      = router.expertIds[i];
r.routerWeight  = router.weights[i];
r.preferredStick= placer.stick[i];
r.routerOrdinal = i;
```

Never recompute IDs or weights in this locality engine.

## 4. Backend EnsureBundle — real residency

`BackendOps::EnsureBundle` must:

- allocate/find a real stick-local bundle allocation;
- upload Gate/Up/Down only on a core cache miss;
- return a stable `DeviceBundleHandle` that names the device buffers/descriptors;
- report actual H2D bytes in `BackendDelta`;
- never claim success with `handle.valid=false`.

A hit in the core never calls `EnsureBundle`, so `EnsureBundle` must not be used as a per-dispatch token/free marker.

`ReleaseBundle` must free/release the entire Gate+Up+Down bundle represented by the handle. It must be safe during model teardown and LRU eviction.

## 5. SubmitExpert — no host bounce

`BackendOps::SubmitExpert` is the decisive live-performance seam.

It must execute Gate/Up/Down from `DeviceBundleHandle`, not from `ExpertBundleView` host pointers. `ExpertBundleView` is supplied for metadata/debug only after residency.

Required dataflow:

```text
stick-local Gate + Up
      ↓
activation / elementwise product
      ↓
stick-local Down
      ↓
× exact routerWeight
      ↓
accumulate into that stick's routed partial
```

On a resident hit, H2D expert-weight bytes should be zero.

The backend should report its real GPU GEMV/GEMM call count through `BackendDelta.gpuGemvCalls`. The core attributes those calls to the selected stick and requires non-zero GPU work on both sticks for DualStick authority.

## 6. Begin/End layer

`BeginLayer` prepares persistent per-stick scratch/partial buffers. Do not allocate scratch per expert.

`SubmitExpert` should enqueue each stick group without a CPU wait after every expert.

`EndLayerReduce` performs the single routed-layer synchronization and merges the two stick-local partial hidden vectors into `routedOut`.

Shared expert execution remains separate and is added after routed reduction, exactly as in the validated K2 architecture.

If a submit or reduction fails, `AbortLayer` must clean queued/transient state. The core records `LAYER_FAILURES>0`, which permanently blocks authority for that measurement window.

## 7. Token/layer call sequence

Per generated token:

```cpp
locality.BeginToken();

for each K2 MoE layer 1..60:
    router.Route(...)
    placer.Place(...)              // IDs/weights unchanged
    locality.ExecuteLayer(...)
    K2MoEExecShared(...)
```

Layer 0 remains the separate dense path.

## 8. Prefetch

`Prefetch(nextLayer, nextSelection, ...)` is safe only after those next-layer expert IDs are already authoritative. It may warm residency; it must never predict/replace the router set.

## 9. Product attestation

Only set `Config::productBackendAttested=true` in the real adapter when:

```text
MOCK_BACKEND=0
RAWRXD_MOCK_BACKEND=0
DUALSTICK_ARMED=1
DEVICE_COUNT>=2
real EnsureBundle device handles live
real SubmitExpert device execution live
real EndLayerReduce live
```

The core still requires:

```text
LAYER_FAILURES=0
SEL==EXE
ACQUIRE_FAIL=0
ROUTER_MUTATION_FAULTS=0
TOPK_DROP_FAULTS=0
GPU0_GEMV_CALLS>0
GPU1_GEMV_CALLS>0
HOST_GEMV_CALLS=0
miss bytes/token < governing baseline
matched host depth/tokens/wall available
DualStick wall/token < matched host wall/token
```

`PROMOTE` remains zero regardless.

## 10. First live acceptance ladder

Do not start with another FULL60 run.

1. Short depth: prove actual bundle handle reuse and `GPU0_GEMV_CALLS>0 && GPU1_GEMV_CALLS>0`.
2. Repeat token/expert set: prove `H2D_BYTES` does not increase on residency hits.
3. Force eviction/re-entry: prove `RELOAD_MISS_BYTES>0` and correctness parity.
4. Matched L32t16 host/DS: prove wall regression is closed.
5. Then run matched L61t8/full-depth locality amortization.
6. Only then evaluate performance authority.
