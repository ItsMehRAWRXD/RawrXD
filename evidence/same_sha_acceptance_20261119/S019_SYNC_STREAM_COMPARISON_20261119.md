# S019 — Same-binary synchronous/stream comparison

## Scope

This run compares the standalone bridge's synchronous and streaming entry points
against the same TinyLlama GGUF and freshly rebuilt executable. The synchronous
mode was added to `tools/release/bridge_lifecycle_test.cpp` and uses the retained
probe input `ping` with an 8-token budget.

## Identity

```ini
SOURCE_SHA=WORKTREE_WITH_Q8_TILE_FIX_AND_TILED4X_FAIL_CLOSED
EXECUTABLE=build_s019_ltt_20261119/bin/Release/deep2_bridge_lifecycle_test.exe
EXECUTABLE_SHA256=650779ECAC143D07C79F53D9BBA67D55D8978EABB52E57A8C8F83862D8AB4DCE
MODEL=models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
MODEL_SHA256=9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
VULKAN_DISABLE=0
```

## Corrected rerun

The tiled Q4_K shader was first corrected for overlapping cohort writes. A
same-binary rerun still produced invalid output, so the tiled pipeline was made
explicit opt-in with `RAWRXD_DEEP2_ENABLE_TILED4X=1`; the default production
path uses the reference Q4_K pipeline.

```ini
CORRECTED_Q8_TILE_INDEXING=IMPLEMENTED
TILED4X_DEFAULT=DISABLED
CORRECTED_BUILD_EXIT=0
CORRECTED_SYNC_EXIT=0
CORRECTED_SYNC_RESPONSE_BYTES=29
CORRECTED_GENERATED_TOKENS=8
CORRECTED_COMPLETED=1
CORRECTED_GPU_DISPATCHES=7
CORRECTED_GPU_FALLBACKS=0
CORRECTED_QUEUE_SUBMITS=7
CORRECTED_S08_LAST_Q_FINITE=1
```

The captured runtime log is
`S019_sync_reference_q4k.log`. It records finite Q samples, completion, eight
generated tokens, and a nonempty 29-byte response.

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
SYNC_RESPONSE_BYTES=29
SYNC_EXIT=0
PREFILL_HIDDEN_STATE=INVALID
FORWARD_FAULT=1
S08_LAST_Q=FINITE
GPU_GEMV_SUCCESS=7
GPU_FALLBACKS=0
GPU_DISPATCHES=7
QUEUE_SUBMITS=7
```

The synchronous path reaches model initialization and Vulkan setup, but fails
before producing a token. The existing stream mode reports the same invalid
prefill signature, so the GUI/stream callback is not the sole cause.

## Disposition

```ini
S019_SAME_INPUT_COMPARISON=PASS_FOR_SYNC_PATH
SHARED_PREFILL_FAILURE=FIXED_BY_REFERENCE_Q4K_SELECTION
TILED4X_CORRECTNESS=OPEN
FIRST_INVALID_OPERATION=TILED4X_Q4K_OUTPUT
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
