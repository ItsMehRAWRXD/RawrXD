# Product binding map

This drop is a planning/measurement layer. Bind it into Deep2's existing live
decode path; do not replace already-passing packed operators.

## Before token execution

Populate `D2RfTokenInput` from the existing residency graph and product counters:

- `packed_weight_bytes`
  - useful packed bytes for the token's selected dense/MoE operators only.
- `vram0_local_bytes`, `vram1_local_bytes`
  - bytes already resident on the GPU that will execute them.
- `ram_bytes`, `mmap_bytes`, `nvme_bytes`
  - bytes still missing from GPU-local residency at token start.
- `*_bw_bytes_per_s`
  - measured sustained values from Deep2 receipts, not vendor peak numbers.
- `gpu*_start_ns`
  - queue/device timestamp start for each same-token lane.

Call:

```c
d2rf_plan_token(&roofline_state, &in, &plan);
```

Use `plan.gpu0_target_bytes/gpu1_target_bytes` as the effective-work target for
the existing completion balancer. Do not independently apply another row-ratio
correction on top of a repetition split that already balances work.

Use `plan.prefetch_budget_bytes` to issue exact-range N+1 residency requests.
Prefetch is asynchronous; token N must never wait on storage I/O merely to make
the receipt look clean.

## After token execution

Fill live measured fields:

- `measured_critical_ns`
- `measured_finish_skew_ns`
- all fail-closed product counters

Then:

```c
d2rf_observe(&roofline_state, &in, &plan);
d2rf_receipt(&in, &plan, &receipt);
```

Only a real product token may satisfy:

```c
d2rf_receipt_authoritative(&receipt) == 1
```

The source self-test cannot mint product authority.

## Recommended live gate

```text
GATE=DEEP2_ROOFLINE_LOCALITY_001
WINDOW=64

required all 64:
  PRODUCT_LINKED=1
  PACKED_NATIVE=1
  MATERIAL_SAME_TOKEN_OVERLAP=1
  OUTPUT_PARITY=1

  COMMAND_REBUILDS=0
  KV_HOST_ROUNDTRIPS=0
  CRITICAL_PATH_NVME_READS=0
  HOST_MATERIALIZATIONS=0
  CPU_F32_EXPANDS=0
  SERIAL_GPU_CHAIN=0
  WEIGHT_MIGRATION=0
  DEVICE_LOST=0

primary:
  median(MEASURED_CRITICAL_NS) decreases

secondary:
  median(BYTES_NOT_LOCAL) decreases
  median(LOCAL_HIT_RATIO_Q16) increases
  median(FINISH_SKEW_NS) decreases

PROMOTE=0
until live product receipts exist.
```
