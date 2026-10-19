# Deep2 No-Dependency Consolidated Source Drop — 2026-09-12

Purpose: consolidate the decode correctness repair and the fifteen remaining performance surfaces into one source-only x64 MASM integration package.

### Build

From a Visual Studio x64 Native Tools command prompt:

```bat
build_masm.bat
```

Output: `build\deep2_nodep.lib`.

### Product integration order

1. Initialize `D2DecodeCtx` with real product callbacks.
2. Seed live state with `Deep2DecodeSeedLiveState`; never infer an AR continuation position from zero.
3. In your real `ForwardFn`, prepare a new token execution generation and run block 0..60 over the current token input while preserving KV/model residency. After real continuity + final norm + LM head, call `Deep2ObserveForward(ctx,61,61,7)` and return the opaque logits/GPU handle plus vocab.
4. Bind a GPU/product selector so full logits need not cross to CPU.
5. Commit the chosen token, advance KV/input state, and let `Deep2RunFullDecode` repeat.
6. Prove 1 token, then 2, then 4/16/64. Do not issue performance authority from compile success.

### Why the opaque logits handle matters

`D2_CTX_LOGITS_HANDLE` is intentionally opaque. It can be a GPU-side reduction object or device buffer identity rather than a host `float*`. That leaves room for the required final-norm -> tiled LM-head -> local top-k -> hierarchical token select path with `FULL_LOGITS_CPU_READBACK=0`.

### Kimi/DeepSeek generality

The ABI contains no Kimi/DeepSeek family names. Expert routing, range tickets, codecs, shard ownership, and residency are all generic descriptors. The same path can therefore bind a 256-expert or 384-expert model without embedding expert count or family policy in the core.

### Status on receipt

```text
SOURCE_DROP=LANDED_LOCALLY
BUILD_STATUS=NOT_RUN_ON_USER_TOOLCHAIN
FULL_MODEL_DECODE=UNPROVEN
FULL_MODEL_TPS_AUTHORITY=0
PROMOTE=0
```
