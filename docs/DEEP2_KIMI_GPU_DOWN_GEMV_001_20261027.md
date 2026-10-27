# DEEP2_KIMI_GPU_DOWN_GEMV_001

This receipt records the bounded GPU0 resident-expert experiment. It is
diagnostic evidence only: it does not enable REAP resizing, change routing, or
authorize a reduced GGUF.

## Provenance

```ini
BASELINE_COMMIT=34fb3dc931e74834142edae19e5f052a45fab656
EXECUTABLE=F:\rawrxd\build_ide\bin\rawrxd_deep2_engine.exe
EXECUTABLE_SHA256=DC3FB90000AE890715DAFADDD3488A42C90AB62E8BA7BEF1FEABE9CE3D7D4455
MODEL_SHARD=F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
PROMPT=The capital of France is
LAYER_LIMIT=2
TOKENS=1
```

The input is the first registered Kimi K2 shard; the native index discovers
the complete 13-shard set. The experiment uses the existing bounded pin budget
(`4096 MiB`) and the opt-in diagnostic variables:

```ini
DEEP2_MOE_GPU_ONLY=1
DEEP2_MOE_GPU_PARITY=1
DEEP2_MOE_GPU_PARITY_LIMIT=1
DEEP2_MOE_ACCOUNTING=1
DEEP2_K2_GPU_MLA=0
```

`DEEP2_MOE_GPU_ONLY` is a test-only admission switch. It opens the existing
Vulkan owner for the MoE worklist while leaving MLA attention on the CPU, so a
CPU/GPU MoE comparison is not confounded by the separate attention kernels.

## Results

```ini
EXIT=0
DUALSTICK_BIND=vc0=1 vc1=0 devices=1
PIN_BUDGET_FINAL_MIB=4096
GPU0_EXPERTS=8
GPU1_EXPERTS=0
GPU_SUBMITS=1
GPU_WAITS=1
H2D_BYTES=228458496
D2H_BYTES=28672
DEVICE_DOWN_VECTORS=8
D2H_PARTIAL_VECTORS=1
HOST_EXPERT_DOWN_VECTORS=0
MOE_GPU_EXECUTION_OBSERVED=1
MOE_GPU_OUTPUT_PATH_OBSERVED=1
MOE_DUAL_GPU_ATTESTED=0
MOE_PRODUCT_BACKEND_ATTESTED=0
MOE_SELECTED=8
MOE_EXECUTED=8
MOE_CPU_EXECUTED=0
MOE_GPU_EXECUTED=8
```

The routed layer-1 expert IDs were `0,44,69,167,223,257,317,365`. The GPU
path completed all eight selected experts and a device partial D2H; no host
expert down vector was used.

The bounded one-expert parity witness was:

```ini
GPU_EXPERT_PARITY layer=1 expert=0 status=OK
max_abs=1.026367489e-02
mean_abs=1.872754886e-03
nonfinite=0
```

The aggregate layer-1 native-versus-CPU witness reported
`maxDiff=4.906482995e-03`, `nonFinite=0`. The CPU baseline and the GPU-MoE-only
run both returned token `13464`. This isolates the earlier full-GPU token
difference (`81147`) to the other GPU MLA path; it is not evidence that the
MoE down-GEMV output was skipped.

## Disposition

```ini
GPU0_RESIDENT_MOE=OBSERVED
GPU0_NUMERICAL_PARITY=DIAGNOSTIC_ONLY
GPU1_EXECUTION=NOT_PROVEN
FULL_GPU_MLA_PARITY=OPEN
REDUCED_GGUF=NOT_GENERATED
REAP_SIZE_RUNTIME=DISABLED
PROMOTE=0
```

The experiment proves real GPU0 routed-expert dispatch and a measured output
path under a bounded resident budget. It does not certify dual-GPU execution,
full-MLA parity, or production `--size` behavior.
