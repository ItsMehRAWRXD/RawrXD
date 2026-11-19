# Canonical quant-weight trim rerun

```ini
MODEL=sha256-f5f1dd8920d417aac2718b0bda3403da274301efdd6760b4f0f4b864ff2ad57d
GPU=AMD_RADEON_AI_PRO_R9700
TOKENS=1
GPU_CALLS=569
CPU_FALLBACKS=0
LIVE_DEVICE_BYTES=289824768
LIVE_DEVICE_ALLOCATIONS=66
HEADROOM_BLOCK57=32321892352
HEADROOM_BLOCK64=32327921664
HEADROOM_PLATEAU=PASS
BLOCK3_ATTENTION_PARITY=FAIL
FULL_REFERENCE_PARITY=NOT_RUN
```

Canonical unpinned-weight trimming prevented the prior monotonic heap decline:
headroom stayed near 30.1 GiB from blocks 57 through 64. Numerical parity remains
an independent blocker.
