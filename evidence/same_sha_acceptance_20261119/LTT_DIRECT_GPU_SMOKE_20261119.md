# LTT direct GPU smoke acceptance

```ini
SOURCE_SHA=4e6aca6e1f867085560712b4dcd2ab3e52738885
EXECUTABLE=F:\\rawrxd\\build\\bin-msvc\\Release\\ltt_tensor_invoke.exe
EXECUTABLE_SHA256=8CF1C86F86B33E3E6B74CC644B499D1CAC5B9ADC4AF592E107B8620D8E514A84
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
DEVICE=0 AMD Radeon AI PRO R9700
COMMAND=ltt_tensor_invoke.exe tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf 1 --repeat=1
EXIT=0
GPU_CALLS=155
CPU_CALLS=0
FINITE_LOGITS=1
RESOURCE_CLEANUP=PASS_REPORTED
```

Observed terminal receipt:

```text
LTT_TOKEN_PASS index=0 repeat=0 position=0 finite_logits=1 top1=2760 gpu_calls=155 cpu_calls=0
LTT_EXECUTE_PASS ... tokens=1 gpu_calls=155 cpu_calls=0
Released all tensors
Vulkan resources cleaned up successfully
```

This closes only the one-token direct LTT GPU smoke gate. Multi-token reference parity and the production IDE GPU-forward gate remain open.
