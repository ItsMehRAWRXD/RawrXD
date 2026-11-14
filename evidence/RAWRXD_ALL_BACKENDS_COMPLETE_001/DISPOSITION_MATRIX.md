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
| Deep2 Vulkan | PARTIAL | Q6K CEBA0DE4 RELATED retained; Q2 MEASURED_ABORT; full family CERT OPEN (L4_P1) |
| Q4_K / Q6_K / Q8 | PARTIAL | Q6K+Q4 RELATED; Q8/Q5/Q3 NOT_RUN; Q2 MEASURED_ABORT ≠ PASS (L4_P1) |
| Packed GEMV / GEMM | PARTIAL | Ornith L3 ULP_CLOSED; specialized sx/batch NOT_RUN; Q2 abort sealed (L4_P1) |
| Attention / KV cache | OPEN | long-context stability TBD |
| Ornith | RELATED | L3 ULP closed; hybrid load/semantic OPEN |
| Laguna / Qwen3.5 | PARTIAL | W1: gate pre-O+TOK>0 tip CEBA0DE4; FIRST_DIVERGENCE_ULP OPEN; PROMOTE=0 |
| MiniMax MoE | PARTIAL | W2 AL12/13 + tip CEBA0DE4 LOAD/MoE OK; FAIL_MID_PREFILL ly=15 TOK=0 SEMANTIC=NOT_RUN; PROMOTE=0 |
| Kimi K2 | PARTIAL / EXPLICIT_UNSUPPORTED gen | W8+L5 tip INDEX 13/13; ProductOpen FAIL DualStick=OFF CAPACITY_PROOF_REOPEN=0; gen=0 EXE `6754616E…` |
| REAP | PARTIAL | H2H OBSERVED_ONLY; MiniMax tip TOK=0; exports rewrite_authorized=0; Ollama sibling FAIL; quality OPEN |
| Strata | PARTIAL | W7: HIP runtime+memcpy PASS (`amdhip64_6`); loaders wired; model E2E EXPLICIT_UNSUPPORTED |
| Ollama | PASS | W7: local :11434 + agent tool emission PASS; PROMOTE=0 |
| Large models 70B/80B/120B | PARTIAL | 3 GGUFs on disk; host load FAIL OOM (TOK=0); DualStick/ICD HOLD; `W3_LARGE_MODEL_NATIVE_001` PROMOTE=0 |
| Multi-agent | RELATED_PARTIAL | `MULTIAGENT_CLI_GUI_PACKAGING_001`: concurrent PASS; cancel PARTIAL; packaging RELATED; GUI E2E NOT_RUN; ≠CERT |

Critical path owner order: Laguna → MiniMax/REAP → large-model → multifamily CLI/GUI → independent CERT.
