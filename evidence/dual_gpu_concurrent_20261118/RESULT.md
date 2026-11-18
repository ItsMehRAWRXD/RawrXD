# Concurrent dual-GPU Deep2 run

```ini
MODEL=qwen2.5-coder_1.5b-base.gguf
PROMPT_TOKENS=1,185
DECODE_TOKENS=2
R9700_EXIT=0
RX7800XT_EXIT=0
```

Both processes were launched before either was awaited.

| Device | Prefill TPS | Decode TPS | E2E TPS | GPU calls | CPU fallbacks | Cleanup |
|---|---:|---:|---:|---:|---:|---|
| AMD Radeon AI PRO R9700 | 1.377 | 2.700 | 1.097 | 601 | 0 | Released all tensors |
| AMD Radeon RX 7800 XT | 1.222 | 2.131 | 0.950 | 601 | 0 | Released all tensors |

```ini
CONCURRENT_DUAL_GPU_EXECUTION=PASS_REPORTED
NUMERICAL_PARITY=NOT_ESTABLISHED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
