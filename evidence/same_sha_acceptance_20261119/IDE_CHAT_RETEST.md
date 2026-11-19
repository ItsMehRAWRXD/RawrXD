# Native Win32 serverless Deep2 chat retest

```ini
SOURCE_SHA=1fcc2c0ecd1487ed71a21c65c42ec695b96c9bec
BUILD_EXIT=0
EXECUTABLE=F:\\rawrxd\\build\\bin\\Release\\RawrXD-Win32IDE-Native.exe
EXECUTABLE_SHA256=823EFF628D361C5D739EA5EC7A1FFFAF9FE564B21EBF696AAFAB92F23CD24231
HTTP_LLAMA_SERVER=STOPPED
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
WM_COMMAND=9614
INIT=1
LOAD=1
GEN=1
GEN_LEN=21
BACKEND=Deep2Engine_GPU_ACTIVE
CPU_FALLBACKS=0
RESPONSE_NONEMPTY=1
PROCESS_EXIT=0
```

Observed response: `inaazzo\n|systemid, It`

The bridge's GPU dispatch and weight-byte counters remain zero on this GUI
status path, so this proves serverless Deep2 chat and zero reported CPU
fallbacks, but does not certify GPU utilization counters or response quality.
