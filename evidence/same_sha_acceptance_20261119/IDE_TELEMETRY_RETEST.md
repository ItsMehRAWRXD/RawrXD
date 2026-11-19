# Win32 Deep2 bridge telemetry retest

```ini
SOURCE_SHA=4de7dbdc4086233ec8a248d8cb93cc1ac5f50753
BUILD_EXIT=0
EXECUTABLE_SHA256=FBE7362AD77497D63F001DD869EE6AAB3D487F038783988505419814EBDD4656
HTTP_LLAMA_SERVER=STOPPED
MODEL=tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
INIT=1
LOAD=1
GEN=1
GEN_LEN=19
BACKEND=Deep2Engine_GPU_ACTIVE
GPU_DEVICES=2
GPU_DISPATCHES=0
GPU_FORWARD_REAL=0
GPU_FORWARD_Q4K_OPS=0
GPU_FORWARD_Q6K_OPS=0
GPU_FORWARD_FALLBACKS=0
CPU_FALLBACKS=0
RESPONSE_NONEMPTY=1
PROCESS_EXIT=0
```

This intentionally records the unresolved telemetry result. The bridge chat
path is serverless and generated text, but the tested path did not establish
real GPU forward execution; no GPU PASS is claimed.
