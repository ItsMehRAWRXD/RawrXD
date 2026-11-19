# TinyLlama operation-trace attempt

```ini
SOURCE_SHA=6a4c02ba5042f978ce69a1cf96082e90bd1bdb12
EXECUTABLE=F:\\rawrxd\\build\\bin\\Release\\deep2_parity_trace.exe
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
TOKENS=1,185,42
EXIT=0
POSITIONS=3
OPS_PER_POSITION=311
GPU_CALLS=0
CPU_CALLS=465
FALLBACK=force_cpu
```

The trace tool produced 311 operation records per position, but this executable selected the CPU diagnostic path (`gpu_calls=0`, `cpu_calls=465`). It is retained as trace infrastructure evidence, not as GPU/reference parity evidence. No kernel change was made from this run.
