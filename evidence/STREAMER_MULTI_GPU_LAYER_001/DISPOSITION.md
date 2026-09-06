# STREAMER_MULTI_GPU_LAYER_001 (2026-09-06)

## Claim

Contiguous transformer-layer placement across multiple opened discrete GPUs.
No round-robin. No SKU hard-codes. Split by DeviceManager score (+ VRAM clamp).

## Live (TinyLlama Q4 → FP32 resident GEMV)

```text
DEEP2_MULTI_GPU_PLAN=ACTIVE
DEEP2_DEVICE_OPENED_COUNT=2
DEEP2_DEVICE_PLANNED_COUNT=2
DEEP2_DEVICE_EXECUTING_COUNT=2

SLOT_0 1002:7551:... layers 0-11   COMPUTE_OPS=1360 UPLOADS=85 HITS=1275
SLOT_1 1002:747E:... layers 12-21  COMPUTE_OPS=1120 UPLOADS=70 HITS=1050

DEEP2_CPU_FALLBACK_USED=0
DEEP2_UNPLANNED_DEVICE_FALLBACKS=0
warm_multi15_e2e_tok_s≈10.0
STREAMER_MULTI_GPU_LAYER_001=PASS
```

Activations cross the split via host-visible I/O already present in GEMV (first gate).
Next: CPU+GPU cooperative placement / transfer-aware migration.
