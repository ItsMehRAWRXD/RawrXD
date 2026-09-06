# STREAMER_HYBRID_ALL_HW_001

## Verdict
**PASS** — planned CPU + GPU layer execution (not discovery-only).

## Witnesses
- `DEEP2_HYBRID_PLAN=ACTIVE`
- `DEEP2_LAYERS_EXECUTED=22/22`
- `DEEP2_REAL_GPU_LAYER_EXEC=1`
- `DEEP2_PLANNED_CPU_GEMV_OPS=224` (trailing layers on `CPU_NATIVE`)
- `DEEP2_PLANNED_GPU_GEMV_OPS=2256`
- `DEEP2_CPU_FALLBACK_USED=0` (planned CPU ≠ fallback)
- `DEEP2_UNPLANNED_DEVICE_FALLBACKS=0`
- warm multi15 ≈ **10.8 tok/s**

## Policy
`RAWRXD_GPU_POLICY=HYBRID` + `RAWRXD_GPU_DEVICES=ALL` + `DEEP2_HYBRID_CPU_LAYERS=2`

## Notes
- Contiguous GPU slots open via DeviceManager; CPU slot attached by `Deep2MultiGpu_AttachPlannedCpu`.
- `forwardLayer` marks per-layer execution; LinearW skips Vulkan on planned CPU slots.
- MARS DualGPUBackend skipped when multi/hybrid plan owns devices (ICD heap conflict).
