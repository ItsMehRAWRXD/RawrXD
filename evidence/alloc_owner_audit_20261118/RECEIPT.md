# Vulkan allocation owner audit

`RR_VULKAN_ALLOC_TRACE=1` on the Qwen3.5 one-token R9700 certifier run.

```ini
MODEL=sha256-f5f1dd8920d417aac2718b0bda3403da274301efdd6760b4f0f4b864ff2ad57d
TOKENS=1
GPU=AMD_RADEON_AI_PRO_R9700
TRACE_ALLOC_EVENTS=509
TRACE_ALLOC_BYTES_SUM=16045580128
DEEP2_LIVE_ALLOCATIONS=66
DEEP2_LIVE_DEVICE_BYTES=289824768
GPU_CALLS=569
CPU_FALLBACKS=0
BLOCK3_ATTENTION_PARITY=FAIL
POST_UNLOAD_BASELINE=NOT_CAPTURED
LEAK_STATUS=NOT_PROVEN
```

The trace shows repeated canonical device-local allocations totaling 16,045,580,128
bytes over the run, while the Deep2-local tracker reports only 289,824,768 live
bytes. These are different accounting domains; the canonical owner must be tracked
through destruction before leak classification.
