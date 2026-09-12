# DEEP2_ROOFLINE_LOCALITY_001 — no-dependency finisher drop

Baseline: `cert/gpu-forward-child-ladder-20260909` after RESIDENCY seal `e80ef647e7` and clean CMake follow-up `c3c147099c`.

This drop closes the **measurement side** of the next 64-token gate. It complements the existing
`src/deep2/d2_roofline.{h,c}` planner; it does not replace it. The existing planner already carries
`bytes_already_local`, `bytes_not_local`, remote tiers, critical bytes and authority eligibility. This
drop provides the byte-true live collector, parent-regression latch, timing window, receipt and verifier.

## Key rule

`BYTES_NOT_ALREADY_LOCAL_PER_TOKEN` is the governing quantity. The cert refuses to invent a pass
threshold. Supply the threshold from the governing gate policy/configuration. Zero/unset means HOLD/FAIL.

## Build selftest

MSVC developer shell:

```bat
cmake -S . -B build -DBUILD_SHARED_LIBS=OFF
cmake --build build --config Release
build\Release\locality64_selftest.exe
```

GCC/Clang:

```sh
cmake -S . -B build
cmake --build build
./build/locality64_selftest
```

Expected selftest only:

```text
DEEP2_ROOFLINE_LOCALITY_SELFTEST=PASS
TOP15_FINISHERS=15/15
LIVE_PRODUCT_RUN=NOT_RUN
PROMOTE=0
```

## Live integration order

1. Copy `Deep2Locality64.hpp/.cpp` into `src/deep2/`.
2. Apply `integration/HOOKS.md` at the real weight/KV/copy/dual-forward sites.
3. Add the library to the same product/cert build graph used by `residency_cert`.
4. Build a dedicated `roofline_locality_cert` beside—not instead of—`residency_cert`.
5. Run one warm token, arm collector, then measure exactly 64 decode tokens.
6. Re-snapshot RESIDENCY counters around that 64-token window.
7. Evaluate with explicit `MAX_NONLOCAL_BYTES_PER_TOKEN` from the gate policy.
8. Write `RECEIPT.txt`; run `scripts/verify_roofline_locality.ps1`.
9. Seal only if `CONJ_OPS` are all 1, `CERT_EXIT=0`, verifier exits 0.
10. Keep `PROMOTE=0` regardless; locality seal only advances the ladder.

## Authority note

The included executable is a **selftest only**. No live product PASS is claimed in this archive.
