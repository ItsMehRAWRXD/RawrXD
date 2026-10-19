# Deep2 consolidated no-dependency source drop

This drop turns the current thread into one x64 MASM ABI package. It is deliberately **authority-safe**: wrappers only mark observations after a bound real product callback returns success. No fixture tensor, synthetic token, synthetic logits, model-family table, Python, Torch, Ollama, llama.cpp, or ROCm runtime is introduced.

## The 15 surfaces

| # | Source | Mechanical role | Authority status after merely compiling |
|---|---|---|---|
| 1 | `deep2_final_norm_lm_head.asm` | real-product callback gate for final norm + LM head | UNPROVEN |
| 2 | `deep2_gpu_token_select.asm` | opaque logits handle -> GPU/product token select | UNPROVEN |
| 3 | `deep2_autoregressive_decode.asm` | position seed, token-generation reset, forward/select/commit/advance loop | UNPROVEN until runtime |
| 4 | `deep2_gpu_rope_kv_attn.asm` | GPU attention callback gate | UNPROVEN |
| 5 | `deep2_moe_router_gpu.asm` | GPU router/top-k callback gate | UNPROVEN |
| 6 | `deep2_expert_dispatch_gpu.asm` | exact-range dispatch callback gate | UNPROVEN |
| 7 | `deep2_grouped_expert_gemv.asm` | grouped top-8 callback gate | UNPROVEN |
| 8 | `deep2_q4_fused_gemv.asm` | direct quant-consume GEMV callback gate | UNPROVEN |
| 9 | `deep2_fused_norm_projection.asm` | fused norm/projection callback gate | UNPROVEN |
|10 | `deep2_fused_residual_norm.asm` | fused residual/next norm callback gate | UNPROVEN |
|11 | `deep2_activation_pingpong.asm` | zero-copy activation handle swap | mechanically implemented |
|12 | `deep2_persistent_decode_plan.asm` | persistent plan callback gate | UNPROVEN |
|13 | `deep2_exact_range_pipeline.asm` + `deep2_exact_range_core.asm` | exact-range N+1 gate + generic descriptor copy | descriptor core implemented; overlap UNPROVEN |
|14 | `deep2_expert_hotset.asm` + gate | exact HOT lookup by region/generation, no family heuristic | lookup implemented; reuse benefit UNPROVEN |
|15 | `deep2_decode_fastpath.asm` | production fastpath callback gate | UNPROVEN |

## Current #03 repair encoded here

1. `Deep2DecodeInit` intentionally does **not** assume prompt length.
2. `Deep2DecodeSeedLiveState` seeds `KV_POSITION`, `PROMPT_TOKENS`, and `EXPECTED_POSITION` from the actual product state.
3. `Deep2DecodeBeginToken` performs only a legal per-token execution reset. It never empties KV or resets the absolute position.
4. The forward callback must re-enter the persistent 61-block executor and call `Deep2ObserveForward` after real 61/61 continuity + final norm + LM head.
5. Selection/commit/advance cannot be reached if forward returns zero, preserving the existing `ERROR_CODE=5 / FORWARD_CALLS=0` boundary.

## Runtime gate ladder

```text
TARGET=1  -> FORWARD=1 SELECT=1 COMMIT=1 ADVANCE=1 GENERATED=1
TARGET=2  -> proves committed/advanced state feeds another full forward
TARGET=4
TARGET=16
TARGET=64 -> only then evaluate sustained decode performance
```

`Deep2AttemptDecodeGrant` may create `D2_AUTH_FULL_DECODE` only when all successful runtime call counters equal `GENERATED` and full-forward observation is present. It does not grant `D2_AUTH_PERF_050MS`; performance authority remains a separate measured gate.

## No-dependency law

```text
EXTERNAL_RUNTIME_DEPS=0
LLAMA_CPP_DEP=0
OLLAMA_DEP=0
PYTHON_RUNTIME_DEP=0
TORCH_DEP=0
ROCM_RUNTIME_REQUIRED=0
MODEL_FAMILY_TABLE_IN_CORE=0
SYNTHETIC_WEIGHT=0
SYNTHETIC_LOGITS=0
SYNTHETIC_TOKEN=0
TENSOR_BINDING_SOURCE=GGUF_METADATA
CODEC_SOURCE=RESOLVED_TENSOR
SHARD_SOURCE=GENERIC_SHARD_INDEX
SCHEDULER_OWNER_COUNT=1
RESIDENCY_OWNER_COUNT=1
ISSUE_COMMIT_OWNER_COUNT=1
DECLARATION_MINTS_AUTHORITY=0
OBSERVATION_MINTS_AUTHORITY=1
NOT_RUN_NE_PASS=1
PROMOTE_FROM_RUNTIME_ONLY=1
```

## Important boundary

The files named for GPU math are ABI-facing gates, not fictional GPU kernels. A source drop cannot honestly claim GPU RoPE/KV/attention, MoE routing, grouped GEMV, Q4 fusion, or a 50 ms token until the existing Deep2 Vulkan/product implementation is bound behind those callbacks and observed. This package gives those implementations one stable, model-independent, no-third-party authority path.
