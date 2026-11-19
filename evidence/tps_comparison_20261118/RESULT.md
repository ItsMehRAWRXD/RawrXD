# Deep2 TPS comparison

```ini
ENGINE_COMMIT=3ef3de6861
MODEL=F:\\rawrxd\\models\\qwen2.5-coder_1.5b-base.gguf
PROMPT_TOKENS=1,185
DECODE_TOKENS=2
RUNS=1
```

| Backend/device | Prefill TPS | Decode TPS | E2E TPS | GPU calls | CPU fallbacks |
|---|---:|---:|---:|---:|---:|
| CPU-pinned | 1.041 | 1.439 | 0.764 | 0 | 591 |
| Vulkan R9700 | 1.120 | 2.612 | 0.922 | 601 | 0 |
| Vulkan RX 7800 XT | 1.101 | 2.062 | 0.869 | 601 | 0 |

Both GPU runs produced finite logits, completed GPU execution, and cleaned up Vulkan resources. The CPU run is explicitly marked `GPU_TPS_VALID=0` by the benchmark because it submitted no GPU work.

```ini
DEEP2_NUMERICAL_CERTIFICATION=NOT_ESTABLISHED
MOE_CERTIFICATION=NOT_APPLICABLE_DENSE_QWEN2_TEST
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
