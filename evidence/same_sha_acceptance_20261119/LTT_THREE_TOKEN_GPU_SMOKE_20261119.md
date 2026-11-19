# LTT three-token direct GPU execution

```ini
SOURCE_SHA=20138a610ab28fec8a8f3493cee4e1ee29d858cf
EXECUTABLE=F:\\rawrxd\\build\\bin-msvc\\Release\\ltt_tensor_invoke.exe
EXECUTABLE_SHA256=8CF1C86F86B33E3E6B74CC644B499D1CAC5B9ADC4AF592E107B8620D8E514A84
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
DEVICE=0 AMD Radeon AI PRO R9700
TOKENS=1,185,42
EXIT=0
GPU_CALLS=465
CPU_CALLS=0
FINITE_LOGITS=3/3
```

Observed:

```text
LTT_TOKEN_PASS index=0 position=0 finite_logits=1 top1=2760 gpu_calls=155 cpu_calls=0
LTT_TOKEN_PASS index=1 position=1 finite_logits=1 top1=13 gpu_calls=310 cpu_calls=0
LTT_TOKEN_PASS index=2 position=2 finite_logits=1 top1=29892 gpu_calls=465 cpu_calls=0
LTT_EXECUTE_PASS ... tokens=3 gpu_calls=465 cpu_calls=0
Released all tensors
Vulkan resources cleaned up successfully
```

This verifies three-token native Vulkan execution only. Independent reference-logit parity and production IDE GPU-forward execution remain open.
