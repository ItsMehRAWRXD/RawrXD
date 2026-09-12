# DEEP2_ENGINE_SSVK_DECODE_BIND16_NODEP_20260912

Authoritative engine-side **16-token** SsVk packed Q2_K decode bind ABI.
Supersedes incomplete Batch2 wiring where they conflict. `PROMOTE=0`.

## Contents

| Path | Role |
|------|------|
| `src/d2_engine_ssvk_bind16.h/.cpp` | C ABI + fail-closed 16/16 window |
| `src/selftest.cpp` | Synthetic 16-token PASS + 72-byte guard |
| `integration/Deep2GpuCounterSnapshot.hpp` | GpuForwardCounters → snapshot |
| `integration/EVIDENCE_EXPORT_ABI.h` | `d2_packed_q2k_product_run_v1` |
| `tools/*.ps1` | Resolve + live verify helpers |
| `build_selftest.bat` | MSVC selftest |

## Geometry

`Q2_K = 84 bytes / 256 weights`. Legacy 72-byte stride is fail-closed
(`stale_72_byte_path_used`).

## Product proof

Dispatch requires `overlap_shorter_pm >= 700`, `overlap_critical_pm >= 500`,
dual real forwards, and the packed-dual conjunction. Commit requires DualStick
slot0/slot1 deltas > 0, host deltas 0, and full transaction notes. Window
authority mints only at 16/16.

## Build

```bat
build_selftest.bat
```

Synthetic PASS ≠ live product run ≠ PROMOTE.
