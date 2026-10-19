# Deep2 batched E2E closure ladder

## Current assumed live boundary

The caller reported material packed dual-GPU overlap at roughly 68.7% over a
16/16 window, with an effective-work distribution near 67.6 / 32.4. Treat that
as input evidence only; this source drop does not re-mint it.

## Batch A — decode finish-time balance

Bind `D2DecodeBalancer` to the calibrated absolute timestamps already emitted by
the dual-GPU gate.

Pass target:

- median `CRITICAL_PATH_NS` beats the frozen baseline;
- median `abs(FINISH_SKEW_NS)` materially falls;
- output parity remains 1;
- material same-token overlap remains 1;
- no device loss, serial chain, migration, synthetic I/O, full dequantization,
  materialized-weight buffer, critical-path NVMe, or external runtime call.

The balancer solves the two lane completion equation and then performs one
aligned signed tail correction. It retains the best critical-path split and
rolls back after >5% regression by default.

## Batch B — persistent decode

Bind the callbacks in `deep2_persistent_decode.h` to the real product engine.

Hard requirements after warmup:

- persistent command/descriptor objects;
- persistent KV owner;
- zero per-token command rebuilds;
- zero KV host round trips;
- N+1 exact-range prefetch;
- zero critical-path NVMe reads;
- 16+ consecutive authority-safe tokens.

## Batch C — residency compiler

Convert each tensor/expert/KV/scratch allocation into `D2ResidencyNode`.

The solver is deliberately simple and deterministic: hard pins first, then a
hotness-per-MiB greedy placement into GPU0/GPU1, RAM, then mmap. It never treats
48 GB of VRAM as one heap and never requires full-model materialization.

For the production planner, enrich the node list with layer/expert lifetime and
device ownership; the ABI can stay unchanged.

## Batch D — live streamer

Bind:

`open_model -> prefill -> decode_one -> emit -> reset -> second generate -> close`

to the native Deep2 path.

`decode_one()` must propagate the real `D2TokenTiming`, including
`external_runtime_calls=0`.

## Batch E — model matrix + endurance

Run the actual installed models. Minimum useful first matrix:

1. BigDaddyG Q2_K ULTRA or CHEETAH — packed dense Q2_K authority.
2. llama3.2-3b-Q2_K — small Q2_K control.
3. one Q4_K_M dense model — quant-generalization control.
4. one MoE model — residency/expert-locality path.

For each: open, generate 64, reset, generate 64, close/reopen, then an extended
run. Promotion remains fail-closed until all mandatory cases pass.

## E2E completion predicate

```text
NATIVE_MODEL_OPEN
&& NATIVE_TOKENIZER
&& REAL_PREFILL
&& REAL_FULL_MODEL_FORWARD
&& REAL_KV
&& REAL_AUTOREGRESSIVE_DECODE
&& REAL_SAMPLER_TOKEN_COMMIT
&& PACKED_NATIVE_WEIGHT_EXECUTION
&& PRODUCT_LINKED_DUAL_GPU
&& MATERIAL_SAME_TOKEN_OVERLAP
&& DECODE_FINISH_BALANCED
&& PERSISTENT_DECODE_STATE
&& ZERO_CRITICAL_PATH_NVME
&& RESIDENCY_PLAN_FIT
&& STREAMING_OUTPUT
&& CANCEL_RESET_REUSE
&& MULTI_GENERATION_SAME_PROCESS
&& MODEL_MATRIX_PASS
&& ENDURANCE_PASS
&& NO_OLLAMA_RUNTIME_DEP
&& NO_LLAMA_CPP_RUNTIME_DEP
&& DEVICE_LOST==0

