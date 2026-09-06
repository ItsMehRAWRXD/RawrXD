# Deep2 topology-agnostic device architecture (2026-09-06)

## Principle

Deep2 is **GPU-topology-agnostic**. Card names (R9700, 7800 XT, …) are
**device records**, not architectures.

```text
Deep2Engine → DeviceManager → ExecutionPlanner → Compute ABI → backends
```

`STREAMER_GPU_SOLO_001` is the first certified implementation of the generic
**single-GPU** path (AUTO picks `best_compute_gpu` by score).

## Policy (env)

| Variable | Meaning |
|----------|---------|
| `RAWRXD_GPU_POLICY=AUTO` | default; score + open one primary |
| `RAWRXD_GPU_DEVICES=CPU` | force CPU_NATIVE |
| `RAWRXD_GPU_DEVICES=0` / `0,2` | open listed DXGI indices (primary = first) |
| `RAWRXD_GPU_DEVICES=ALL` | multi later; today still opens best single |
| `DEEP2_GPU_SELECT` / `RAWRXD_GPU_NAME` | name-substring filter (SOLO override) |

## Witnesses (generic)

```text
DEEP2_DEVICE_COUNT_DETECTED=<n>
DEEP2_DEVICE_COUNT_OPENED=<n>
DEEP2_DEVICE_i_NAME / VENDOR / IDENTITY / VRAM / SCORE / DUTY
```

DUTY values: `DETECTED/UNUSED` | `COMPUTE_PRIMARY` | (later: DRAFT, PARTITION)

## Backends under Compute ABI

`CPU_NATIVE | VULKAN | CUDA* | HIP* | DIRECTML* | UMA_SHARED*`  
(* optional / later)

Transformer code must not branch on vendor strings.
