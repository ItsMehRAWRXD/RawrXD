# RAWRXD_DUALSTICK_LOCALITY_ENTERPRISE_001

Production-hardened, dependency-free C++17 source drop for K2 routed-expert locality and DualStick execution control.

## Scope

This drop fixes the performance architecture exposed by the Kimi K2 DualStick experiments without changing router quality semantics:

- router-selected expert IDs and router weights are immutable;
- scheduling may reorder selected experts by stick only;
- Gate + Up + Down are one atomic `(layer, expert)` residency bundle;
- a resident bundle is never reacquired by the core;
- stable owned host staging prevents pointer churn from defeating downstream pin/cache identity;
- work is grouped into one list per stick with one routed-layer begin/end reduction boundary;
- misses are split into compulsory first-touch bytes vs reload bytes;
- thrash never truncates top-k: the whole routed layer fails before expert execution;
- product performance authority is fail-closed and cannot be minted by the selftest/mock backend;
- `PROMOTE=0` is hard-coded in authority evaluation/receipts.

No third-party source or runtime library is included. The core uses only the C++17 standard library. RawrXD/Vulkan integration is supplied through callback contracts so the standalone core remains independently buildable.

## Why this drop exists

The live K2 branch showed that routed expert Gate/Up/Down slices were read into new host vectors for each expert execution, while the GPU helper performed DualStick acquire calls and then still dispatched GEMV from host buffers. That permits placement counters to advance without proving reusable stick-local expert execution. This package moves residency identity above the per-expert execution call and makes device residency an explicit reusable bundle handle.

## Current authority boundary

This source drop does **not** claim the projected 35–50 TPS target.

```text
PRIOR_FULL_HOST_SEAL=2d0f2dc480
FULL_HOST_MOE_EXECUTION=PASS
PRIOR_HOST_EXPERT_MISS_BYTES_PER_TOKEN=33564101
DUALSTICK=HOLD
TPS_PERFORMANCE_AUTHORITY=0
TARGET_35_50_TPS=UNMINTED
PROMOTE=0
```

The current matched-depth observation supplied to this work is approximately 10.1 s/token host vs 11.0 s/token DualStick at L32t16. That is a regression/HOLD, not a performance PASS. A full-depth matched comparison remains a separate live gate.

## Top-15 locality fixes covered

| # | Fix | Ownership in this drop |
|---:|---|---|
| 1 | No reacquire for resident expert | **Core enforced** |
| 2 | Gate+Up+Down atomic residency bundle | **Core enforced** |
| 3 | Placement output consumed directly by executor | **Core request/handle contract** |
| 4 | No host bounce on residency hit | **Backend contract**; core never reacquires hit |
| 5 | Persistent per-stick scratch | **Backend contract** |
| 6 | Batch top-k experts by stick | **Core enforced** |
| 7 | One synchronization/reduction boundary per MoE layer | **Core enforced** |
| 8 | Gate+Up dispatch fusion | **Backend optimization seam** |
| 9 | Keep Down output device-side until weighting | **Backend contract** |
| 10 | Stick-local partial sums, then one merge | **Backend contract via Submit/EndLayerReduce** |
| 11 | Load-aware cold placement | **Core optional fallback** |
| 12 | Residency key is `(layer, expert)` | **Core enforced** |
| 13 | Whole-bundle eviction | **Core enforced** |
| 14 | Next-layer prefetch seam | **Core implemented** |
| 15 | Compulsory/reload/hit byte accounting | **Core implemented** |

The real RawrXD backend must satisfy #4/#5/#8/#9/#10 for the live product path; the core deliberately refuses to infer GPU execution from assignment counters alone.

## Source layout

```text
include/deep2/EnterpriseDualStickLocality.hpp  public API/contracts
src/EnterpriseDualStickLocality.cpp           cache/scheduler/authority core
tests/selftest.cpp                            dependency-free deterministic tests
adapter/RAWRXD_K2_BIND.md                     exact K2 integration contract
AUTHORITY_LAW.txt                             fail-closed product law
SECURITY.md                                   lifetime/failure hardening notes
evidence/SELFTEST_RECEIPT.txt                 generated non-product receipt
build_msvc.bat                                VS 2022 x64 build+selftest
build_linux.sh                                C++17 build+selftest
CMakeLists.txt                                optional build-system entry
```

## Build — Windows/MSVC

From a VS 2022 x64 Developer Command Prompt:

```bat
build_msvc.bat
```

The batch uses `/std:c++17 /W4 /WX /permissive- /sdl` and runs the selftest.

## Build — Linux/Clang/GCC

```sh
./build_linux.sh
```

The script uses C++17, strict warnings, and `-Werror`, then runs the selftest.

Optional CMake:

```sh
cmake -S . -B build-cmake
cmake --build build-cmake --config Release
ctest --test-dir build-cmake --output-on-failure
```

## Live RawrXD bind

Read `adapter/RAWRXD_K2_BIND.md`. The critical rule is that `BackendOps::EnsureBundle` must return a reusable handle for real stick-local Gate/Up/Down weights and `BackendOps::SubmitExpert` must execute from that handle. Calling the existing host-pointer `DispatchGEMVQuant` after an acquire is not sufficient proof of resident execution.

Set:

```cpp
cfg.productBackendAttested = true;
```

**only** after the live adapter has established all of:

```text
MOCK_BACKEND=0
DUALSTICK_ARMED=1
DEVICE_COUNT>=2
EnsureBundle = real device residency
SubmitExpert = real device-handle execution
EndLayerReduce = real stick-local partial merge
```

Even with attestation, performance authority additionally requires structural parity, both sticks executing GPU GEMV, improved miss bytes/token, a matched-depth/matched-token host wall comparison, and improved wall time.

## Governing metrics

The drop reports both:

```text
EXPERT_MISS_BYTES_PER_TOKEN = (compulsory + reload) / tokens
RELOAD_MISS_BYTES_PER_TOKEN = reload / tokens
```

Use total miss bytes/token for the current sealed baseline comparison, and use reload bytes/token to diagnose whether steady-state residency is actually improving after first touch.

## Quality invariants

The core fingerprints router ID/weight/order before and after execution. `preferredStick` is intentionally excluded from the quality fingerprint because it is scheduling metadata only.

```text
selected IDs = executed IDs
router weights unchanged
execution order may change
thrash never drops top-k
shared expert remains outside this routed-expert engine
```

## Selftest authority

The included selftest intentionally uses `productBackendAttested=false`. It may prove implementation mechanics, but it **cannot** mint live product TPS authority. Its receipt must retain:

```text
PRODUCT_BACKEND_ATTESTED=0
TPS_PERFORMANCE_AUTHORITY=0
TARGET_35_50_TPS=UNMINTED
PROMOTE=0
```
