# S019 — Same-binary synchronous/stream comparison

## Scope

This run compares the standalone bridge's synchronous and streaming entry points
against the same TinyLlama GGUF and freshly rebuilt executable. The synchronous
mode was added to `tools/release/bridge_lifecycle_test.cpp` and uses the retained
probe input `ping` with an 8-token budget.

## Identity

```ini
SOURCE_SHA=UNCOMMITTED_WORKTREE_AT_TEST_TIME
EXECUTABLE=build_s019_ltt_20261119/bin/Release/deep2_bridge_lifecycle_test.exe
EXECUTABLE_SHA256=D74090031E271E4759B0CF2D55B2AA5647A60E1C52B491A5ED4FB599E9FE2E70
MODEL=models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
VULKAN_DISABLE=0
```

## Commands

```powershell
cmake --build build_s019_ltt_20261119 --config Release --target deep2_bridge_lifecycle_test -- /m:6
$env:RAWRXD_BRIDGE_DISABLE_VULKAN='0'
deep2_bridge_lifecycle_test.exe <model> --sync
```

## Observed result

```ini
BUILD_EXIT=0
SYNC_PROMPT=ping
SYNC_MAX_TOKENS=8
SYNC_RESPONSE_BYTES=0
SYNC_EXIT=6
PREFILL_HIDDEN_STATE=INVALID
FORWARD_FAULT=1
S08_LAST_Q=NaN
GPU_GEMV_SUCCESS=0
GPU_FALLBACKS=0
GPU_DISPATCHES=0
QUEUE_SUBMITS=202
```

The synchronous path reaches model initialization and Vulkan setup, but fails
before producing a token. The existing stream mode reports the same invalid
prefill signature, so the GUI/stream callback is not the sole cause.

## Disposition

```ini
S019_SAME_INPUT_COMPARISON=COMPLETE
SHARED_PREFILL_FAILURE=CONFIRMED
FIRST_INVALID_OPERATION=Q_OUTPUT_OR_PREFILL_PATH_UNRESOLVED
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
