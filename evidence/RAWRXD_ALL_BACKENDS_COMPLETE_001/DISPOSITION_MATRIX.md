# RAWRXD_ALL_BACKENDS_COMPLETE_001 — Disposition Matrix

```text
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
METHOD_C_COMPLETE=1 ≠ this program CERT
NOT_RUN!=PASS CROSS_SHA_CREDIT=0
```

Status legend: **OPEN** | **RELATED** | **PARTIAL** | **CERTIFIED** | **EXPLICIT_UNSUPPORTED** | **N/A**

| Workstream | Status | Notes / SSOT pointer |
|------------|--------|----------------------|
| Deep2 CPU | OPEN | quantized parity + perf TBD |
| Deep2 Vulkan | PARTIAL | Q6K SPV RELATED/R105 VERIFY; host fallback ≠ GPU cert |
| Q4_K / Q6_K / Q8 | PARTIAL | Q6K attn_v path advanced; full family OPEN |
| Packed GEMV / GEMM | PARTIAL | Ornith L3 ULP_CLOSED vs f32 (R104); shapes/batches OPEN |
| Attention / KV cache | OPEN | long-context stability TBD |
| Ornith | RELATED | L3 ULP closed; hybrid load/semantic OPEN |
| Laguna / Qwen3.5 | PARTIAL | WS1 REAP_LAGUNA=PARTIAL; stop@ATTN_GATE_PARITY=NOT_RUN; TOK RELATED≠parity; PROMOTE=0 |
| MiniMax MoE | PARTIAL | W2 seal: router MATCH; expert map AL12 OK; AL13 STATIC PASS; FFN_DOWN_1 BOUNDED_OPEN; AL14 OPEN; Ollama create FAIL; PROMOTE=0 |
| Kimi K2 | PARTIAL | tip INDEX 13/13; PRODUCT_OPEN_FAIL_NOT_STREAMABLE; gen=0; `K2_L5_P1_TIP_LOAD_001` EXE `6754616E…` |
| REAP | PARTIAL | H2H OBSERVED_ONLY; on-disk exports present rewrite_authorized=0; MiniMax REAP24 split KV OK / Ollama sibling FAIL; quality OPEN |
| Strata | NOT_RUN | HIP native E2E NOT_RUN; product amdhip64.dll FAIL; versioned runtime AVAILABLE (n=2); Feature NOT_IMPL; L6L7_STRATA_HIP_OLLAMA_001 |
| Ollama | PARTIAL | local HTTP gen remasure PASS + tools API smoke PASS; REAP H2H PARTIAL 3/6; product AgentOllama E2E OPEN; L6L7_STRATA_HIP_OLLAMA_001 |
| Large models 70B/80B/120B | NOT_RUN | PATH_ABSENT on disk; seal `K2_L5_P1_TIP_LOAD_001` |
| Multi-agent | PARTIAL | dual-ws isolation PASS (`CLI_AGENT_CONCURRENCY_001`); cancel OPEN (acceptSteer=false); Method C + FORCE_TOOL retained exact-SHA |

Critical path owner order: Laguna → MiniMax/REAP → large-model → multifamily CLI/GUI → independent CERT.
