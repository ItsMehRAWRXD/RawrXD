# STREAMER_GPU_RESIDENT_DECODE_001

## Verdict
**PASS** — live `generateStream` consumes resident forward.

## Witnesses
- `LIVE_DECODE_RESIDENT_FORWARD=1`
- `LIVE_DECODE_COMMITTED=1`
- `DEEP2_REAL_GPU_FORWARD=1`
- `TOKENS_DECODED=15`
- `GPU_FORWARD_LAYERS_PER_TOKEN=22`
- `HOST_FORWARD_LAYER_CALLS=0`
- `DEEP2_GPU_FORWARD_HOST_MATERIALIZATIONS=0`
- fallback / unplanned = 0
- warm multi15 ≈ **8.59 tok/s**

## Path
```
generateStream → forwardTokenAllLayers → forwardGpuMultiMap / Contiguous
→ sample → next token
```
Medusa skipped when resident GPU decode enabled.
