# RAWRXD_ALL_BACKENDS_COMPLETE_001 � Backend completion matrix

```text
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
TIP_CLIMB=HOLD GATE_STOP=1
BASELINE_TIP=CEBA0DE4�
```

Honest statuses: `SEALED` | `PARTIAL` | `OPEN` | `NOT_RUN` | `BLOCKED` | `N/A`.  
A track is `CERTIFIED` only when all 8 levels pass on one traceable EXE SHA.

Certification levels: Build � Load � Numerics � Generation � Performance � Reliability � Integration � Packaging.

---

## Workstream board

| ID | Workstream | Status | Levels cleared (honest) | Blocking next | Evidence pointer |
|----|------------|--------|-------------------------|---------------|------------------|
| W01 | Deep2 CPU | PARTIAL | TinyLlama Q4_K host short+med CE=1 (WS5); full quant parity OPEN | Host Q-family parity + ref dump | ATTN_KV_DEEP2_CPU_001 + CLI_NUMERICAL |
| W02 | Deep2 Vulkan | RELATED | WS3 family; Q6 CEBA verified; Q8 PASS; ≠ CERT | Tip FORCE_SPV + long-ctx | DEEP2_VULKAN_QK_GEMV_FAMILY_001 |
| W03 | Q4_K / Q6_K / Q8 kernels | RELATED | Q8/Q5/Q3/Q2 PASS; Q4 numeric OK/GATE_FAIL; Q6 PARITY_OK | Q4K tps / tip remasure | DEEP2_VULKAN_QK_GEMV_FAMILY_001 |
| W04 | Packed GEMV / GEMM | PARTIAL | Ornith L3 ULP CLOSED; W5 Q4 packed shapes PASS; GEMM batch OPEN | Broader batch/shape matrix | W5 + BR_ORNITH_PACKED_GEMV_L3_R104 |
| W05 | Attention / KV cache | PARTIAL | TinyLlama short+medctx KV CE=1 (38 grows); PT1784 trunc; FIRST_DIVERGE attn RELATED; Laguna ULP OPEN | PT>=1024 CLEAN_EXIT + host ref dump + Laguna ULP | ATTN_KV_DEEP2_CPU_001 + FIRST_DIVERGE + W1_LAGUNA |
| W06 | Ornith | PARTIAL | L3 ULP held; tip prefill L0–L40 FINITE; Deep2 SEMANTIC=FAIL (HEAP/TOK=0); llama HYBRID_LOAD=PASS peer | POST_L40 heap/logits + PROD_DECODE + coherent TOK | ORNITH_BEYOND_L3_001 + W6_ORNITH_HYBRID_COMPLETE + R101–R105 |
| W07 | Laguna / Qwen3.5 | OPEN | Tensor map L0/1/40 CLOSED; order MATCH softplus-before-O; digests L0+L40 RUNTIME; NUMERIC_PARITY OPEN | `REAP_LAGUNA_ATTN_GATE_001` FIRST_DIVERGENT=OPEN_NUMERIC (NO_BITEXACT_REF_DIGEST_COMPARE) EXE=57D6EB21 | FAIR_H2H + R100 + ATTN_GATE_001 |
| W08 | MiniMax MoE | PARTIAL | Router MATCH+AL12/13; tip CEBA0DE4 LOAD/MoE OK; FAIL_MID_PREFILL ly=15 TOK=0 SEMANTIC=NOT_RUN; Ollama create FAIL | Survive 62L->TOK>0 + FFN_DOWN_1 GPU A/B + AL14 | W2_MINIMAX_REAP_SEMANTIC + FAIR_H2H P0-D |
| W09 | Kimi K2 | PARTIAL / EXPLICIT_UNSUPPORTED gen | Tip INDEX 13/13; ProductOpen FAIL DualStick=OFF; GENERATED_TOKENS=0 | Streamable working-set + native gen | W8_KIMI_K2_MULTI_AGENT_001 + K2_L5_P1_TIP_LOAD_001 |
| W10 | REAP | PARTIAL | Physical exports rewrite_authorized=0; Laguna TOK peer; MiniMax tip TOK=0; Ollama create FAIL; quality!=competitive | Fair H2H after TOK32; MiniMax SEMANTIC | W2_MINIMAX_REAP_SEMANTIC / REAP_STRATA_* |
| W11 | Strata (HIP) | PARTIAL | Runtime+memcpy PASS (`amdhip64_6` n=2); product loaders wired; model E2E EXPLICIT_UNSUPPORTED (no hipcc kernels) | HIP kernel/model forward path | W7_STRATA_HIP_OLLAMA_001 |
| W12 | Ollama | PASS | Local version/tags/generate PASS; agent tool emission PASS (calculator); roundtrip final TIMEOUT not credited | Concurrency/cancel TBD | W7_STRATA_HIP_OLLAMA_001 |
| W13 | Large models 70/80/120B | PARTIAL | 3 GGUFs tried host-floor; LOAD_FAIL OOM; TOK=0; DualStick/ICD HOLD | Host residency or authorized DualStick | W3_LARGE_MODEL_NATIVE_001 |
| W14 | Multi-agent | PARTIAL | MODEL_LOADED concurrent PASS (CEBA0DE4); cancel PARTIAL; lanes PASS; packaging RELATED; GUI select NOT_RUN | in-proc CancelGeneration + GUI multifamily E2E + gemma3 | MULTIAGENT_CLI_GUI_PACKAGING_001 |

---

## Eight parallel engineering lanes (execution map)

| Lane | Owns | Critical-path priority |
|------|------|------------------------|
| L1 | Laguna first-divergence ULP (order CLOSED; parity residual) | **P0 residual** |
| L2 | MiniMax MoE router/experts + REAP semantic | P0 |
| L3 | Ornith SEMANTIC beyond L3 ULP | P1 |
| L4 | Vulkan Q-family + packed GEMV shape matrix | P1 |
| L5 | K2 multi-shard + large-model load | P1 — W8+L5: index OBSERVED; gen EXPLICIT_UNSUPPORTED on host |
| L6 | Strata HIP native + benchmark | P2 |
| L7 | Ollama integration + agent tool | P2 |
| L8 | Multi-agent concurrency / cancel / isolation | P2 — WS8 MULTIAGENT pack: concurrent PASS; cancel PARTIAL; packaging RELATED |

---

## Program gates

```text
PROGRAM_COMPLETE=0
ANY_TRACK_CERTIFIED=0
ENTERPRISE=0/128
SAME_DAY_FULL_CERT=NOT_GUARANTEED
NEXT_LEGAL=Laguna FIRST_DIVERGENCE_ULP → MiniMax/REAP semantic → large-model native → multifamily CLI/GUI → independent cert
WS1_ABSORB=W1_LAGUNA_NUMERICAL_PARITY_001 PARTIAL EXE=CEBA0DE4 tip + 30896EA4 trial PERF_CREDIT=0
```

