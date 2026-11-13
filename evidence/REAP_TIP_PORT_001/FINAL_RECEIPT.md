# REAP live-size tip finish

Timestamp: 2026-11-12  
Executable: `build_ninja/bin/rawr.exe`  
SHA-256: `74C10C28C5BC5311DD9CF88681DCB761FD4B7698504CBF11B82D33BCC361C2D8`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0`

## Product interface

```text
rawr run <model> --reap <params>/<experts> -p "..." [--max-tokens N] [--receipt R]
rawr run <model> --size  <params>/<experts> -p "..."
```

## Controlling defect closed (Batch 01–03)

`kn` in `gate GEMV failed type=12 kn=null` = `GEMVKernelFn*` from
`QuantKernelRegistry::GetGEMV(12)`. Null because K2 `INDEX_AND_ADDRESS`
skipped `Initialize()`. DualStick-unbound host path now runs host expert GEMV.

## Same-SHA verification (`74C10C28…`)

| Case | Result |
|---|---|
| Host floor Kimi `--reap 30GB/8` 61L × 8 tok | EXIT=0 GENERATED_TOKENS=8 experts_executed=3840 parity=1 HOST_GEMV=3840 CLEAN_EXIT ~136s |
| L1 residual + join invariants | PASS=1 (maxAbs ≈ 1e-9 / 4e-10) |
| `RAWRXD_ALLOW_GPU=1` 2L DualStick | VC bind non-null; EXPERT_GPU_EXEC=8 HOST_GEMV=0 TRUE_RUNTIME=1 GENERATED_TOKENS=1 |
| Independent reference token parity | OPEN |
| Multi-GPU / full-61 GPU | NOT_TESTED (2L GPU only) |
| Offline writer | HELD |

Artifacts: `evidence/REAP_TIP_PORT_001/k2gen/`  
(`g05_full61_t8_sha74.*`, `g07_gpu_vcbind.*`, `G01_G05_HOST_NATIVE_RECEIPT.md`)

## Disposition

```text
K2_GATE_GEMV=PASS
K2_HOST_NATIVE_GENERATION=PASS
K2_L1_RESIDUAL_JOIN=PASS
K2_GPU_DUALSTICK_2L=PASS
K2_GPU_FULL61=NOT_TESTED
K2_REFERENCE_PARITY=OPEN
REAP_ACTIVE_RUNTIME_ROUTER_RESIDENCY=PASS
CERTIFIED=0
PROMOTE=0
NEXT_GATE=REFERENCE_PARITY_OR_FULL61_GPU
```
