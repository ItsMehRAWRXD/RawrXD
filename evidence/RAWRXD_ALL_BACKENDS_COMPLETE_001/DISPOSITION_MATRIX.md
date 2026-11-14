# RAWRXD_ALL_BACKENDS_COMPLETE_001 — Disposition Matrix

```text
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
METHOD_C_COMPLETE=1 ≠ this program CERT
NOT_RUN!=PASS CROSS_SHA_CREDIT=0
```

Status legend: **OPEN** | **RELATED** | **PARTIAL** | **CERTIFIED** | **EXPLICIT_UNSUPPORTED** | **N/A**

| Workstream | Status | Notes / SSOT pointer |
|------------|--------|----------------------|
| Deep2 CPU | RELATED/PARTIAL | WS5 TinyLlama Q4_K host short+med CE=1; full quant matrix OPEN |
| Deep2 Vulkan | RELATED | WS3 `DEEP2_VULKAN_QK_GEMV_FAMILY_001`; host fallback ≠ GPU cert |
| Q4_K / Q6_K / Q8 | RELATED | Q6 FORCE_SPV CEBA exact-SHA; Q8 shapes PASS; Q4 numeric OK/GATE_FAIL |
| Packed GEMV / GEMM | PARTIAL | Ornith L3 ULP_CLOSED; Q4/Q8 shapes expanded; GEMM multi-batch OPEN |
| Attention / KV cache | PARTIAL | `ATTN_KV_DEEP2_CPU_001` medctx KV stable; PT1784 trunc; FIRST_DIVERGE RELATED |
| Ornith | RELATED_PARTIAL | L3 ULP held; tip prefill L0–L40 FINITE; Deep2 SEMANTIC=FAIL HEAP/TOK=0; llama HYBRID_LOAD=PASS; ORNITH_BEYOND_L3_001 |
| Laguna / Qwen3.5 | PARTIAL | W1: gate pre-O+TOK>0 tip CEBA0DE4; FIRST_DIVERGENCE_ULP OPEN; PROMOTE=0 |
| MiniMax MoE | PARTIAL | W2 AL12/13 + tip CEBA0DE4 LOAD/MoE OK; FAIL_MID_PREFILL ly=15 TOK=0 SEMANTIC=NOT_RUN; PROMOTE=0 |
| Kimi K2 | RELATED | `KIMI_K2_LARGE_MODELS_001`: tip INDEX 13/13; GEN BLOCKED_OOM NOT_STREAMABLE TOK=0 EXE `6754616E…`; TIP005 RELATED BACKEND_SELECT OOM CROSS_SHA=0 |
| REAP | PARTIAL | H2H OBSERVED_ONLY; MiniMax tip TOK=0; exports rewrite_authorized=0; Ollama sibling FAIL; quality OPEN |
| Strata | PARTIAL | W7: HIP runtime+memcpy PASS (`amdhip64_6`); loaders wired; model E2E EXPLICIT_UNSUPPORTED |
| Ollama | PASS | W7: local :11434 + agent tool emission PASS; PROMOTE=0 |
| Large models 70B/80B/120B | RELATED | `KIMI_K2_LARGE_MODELS_001`: 70B FAIL_SEH; 80/120 BLOCKED_OOM/FAIL_SEH; TOK=0; peer `W3_LARGE_MODEL_NATIVE_001`; PROMOTE=0 |
| Multi-agent | RELATED_PARTIAL | `MULTIAGENT_CLI_GUI_PACKAGING_001`: concurrent PASS; cancel PARTIAL; packaging RELATED; GUI E2E NOT_RUN; ≠CERT |

Critical path owner order: Laguna → MiniMax/REAP → large-model → multifamily CLI/GUI → independent CERT.
