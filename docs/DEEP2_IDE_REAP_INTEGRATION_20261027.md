# RawrXD IDE + Deep2 + REAP integration receipt

This receipt binds the native IDE shell, Deep2 runtime, and REAP diagnostics to
one source checkout. It records what was executed locally and keeps remaining
production gates explicit.

## Provenance

```ini
BRANCH=fix/deep2-multimodel-safety-20261025
SOURCE_COMMIT=db6bb67cba8f91dd6f902da277d05033c2f2e8c6
BACKUP_BRANCH=backup/local-working-tree-20261027
BACKUP_HEAD=db6bb67cba8f91dd6f902da277d05033c2f2e8c6
```

Both branch heads were pushed to `origin` and resolved to the same commit.

## Build and runtime evidence

```ini
DEEP2_TARGET=rawrxd_deep2_engine
DEEP2_EXE_SHA256=4CFC78A7EF6A6C889F16D4EC6A815938CC2AF2CD6E5E60E9C249CE60636389AA
DEEP2_KIMI_ONE_TOKEN_EXIT=0
DEEP2_KIMI_T0_L39_EXIT=1
DEEP2_KIMI_QUIET_WALL_NS=50696723000
DEEP2_KIMI_GPU_GEMV_NS=0
DEEP2_KIMI_H2D_BYTES=0
DEEP2_KIMI_GPU1=NOT_PROVEN

IDE_TARGET=RawrXD-Win32IDE-Native
IDE_EXE_SHA256=505B27490A83C4D6ECCF4F46250919EABDD003F8700743402A87A3C096C93B6C
IDE_BUILD=PASS
HEALTH_PROBE=PASS
HEALTH_PROBE_EXIT=0
PRODUCTION_HARDENING_TESTS=77/77
PRODUCTION_HARDENING_EXIT=0
```

The production test update verifies the implemented audit policy: a damaged
tail is quarantined, the original bytes remain available, and a fresh active
chain is opened and verified.

## REAP/Kimi attribution evidence

With `DEEP2_MOE_ACCOUNTING=1`, the real Kimi route executed 480 selected and
480 completed experts across 60 MoE layers. All 480 were CPU executions, with
zero GPU executions and zero acquisition hits in that run. The measured expert
total was 48.132579 seconds, including 26.369516 seconds of down-projection
GEMV. The detailed receipt is documented in
`DEEP2_KIMI_PERFORMANCE_ACCOUNTING_20261027.md`.

This is an attribution result, not a claim of REAP pruning or GPU speedup.
The existing model shards were read-only; no reduced GGUF was produced.

## Release boundary

```ini
IDE_NATIVE_BUILD=PASS
IDE_HEALTH=PASS
DEEP2_KIMI_ONE_TOKEN=PASS_REPORTED
REAP_EXPERT_ATTRIBUTION=PASS_DIAGNOSTIC
GPU1_REAL_COMPUTE=NOT_PROVEN
GPU_RESIDENT_MOE=NOT_PROVEN
NUMERICAL_REFERENCE_PARITY=OPEN
REDUCED_GGUF=NOT_GENERATED
REAP_SIZE_RUNTIME=DISABLED
PROMOTE=0
```

The next authorized engineering step is a bounded resident expert-slice
experiment and a separately certified GPU dispatch path. Those changes must
be measured against the quiet-binary receipt and must not enable `--size` until
reference parity and writer round-trip gates pass.
