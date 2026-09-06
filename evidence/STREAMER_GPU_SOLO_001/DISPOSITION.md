# STREAMER_GPU_SOLO_001 — disposition (2026-09-06)

## Architecture (locked)

Deep2 is **GPU-topology-agnostic**. Card SKUs are device records, not code paths.

```text
Deep2Engine → DeviceManager → ExecutionPlanner → Compute ABI → backends
```

`STREAMER_GPU_SOLO_001` certifies the generic **single-GPU** path.
First certified instance on this host: AUTO `best_compute_gpu` (largest discrete VRAM).

```text
CPU_NATIVE CERTIFIED 10/10
        │
        ▼
STREAMER_GPU_SOLO_001   ← SingleGpu (AUTO primary)
        │
        ▼
STREAMER_GPU_SOLO_002   ← alternate single device (user select / 2nd discrete)
        │
        ▼
STREAMER_SPECULATIVE_001
        │
        ▼
STREAMER_MULTIGPU_001
        │
        ▼
STREAMER_AUTOTUNE_001
```

## Policy

| Env | Effect |
|-----|--------|
| `RAWRXD_GPU_POLICY=AUTO` | score + open one primary |
| `RAWRXD_GPU_DEVICES=CPU` | force CPU_NATIVE |
| `RAWRXD_GPU_DEVICES=0` / `0,2` / `ALL` | user open list |
| `DEEP2_GPU_SELECT` / `RAWRXD_GPU_NAME` | name / stable-id filter |

## Witnesses (generic)

```text
DEEP2_DEVICE_COUNT_DETECTED=<n>
DEEP2_DEVICE_COUNT_OPENED=1
DEEP2_DEVICE_i_NAME / VENDOR / STABLE_ID / VRAM / SCORE / DUTY
DEEP2_PRIMARY_NAME=...
DEEP2_COMPUTE_BACKEND=GPU
DEEP2_GPU_COMPUTE_ACTIVE=1
DEEP2_REAL_GPU_GEMV=1   (partial: GEMV path)
DEEP2_REAL_GPU_FORWARD=0 until resident weights + full layer chain
```

## Certified CPU floor (immutable)

```text
DEEP2_COMPUTE_BACKEND=CPU_NATIVE
TinyLlama multi15 decode ≈ 12.1–12.6 tok/s
BENCH_64 frozen baseline = 8.52
```

## Current SOLO blocker

`UPLOAD_BOUND_NO_RESIDENT_WEIGHTS` — GEMV works; e2e tok/s low until weights stay in DEVICE_LOCAL.
