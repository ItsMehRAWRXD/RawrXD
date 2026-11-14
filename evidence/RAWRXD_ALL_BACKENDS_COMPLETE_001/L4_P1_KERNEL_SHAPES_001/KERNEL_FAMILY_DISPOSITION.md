# L4 P1 — Kernel family disposition

```text
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
INVENT_PASS=0 NOT_RUN!=PASS CROSS_SHA_CREDIT=0
MEASURE_EXE=CEBA0DE4734A3897B96A825C5CE16685161DB8A3C570C22F6B06B3DE4368A3C5
TIP_EXE_OBSERVED=1BE8F02A… (no credit)
```

| Family / shape | SPV / path | Status | Evidence / blocker |
|----------------|------------|--------|---------------------|
| Q6_K packed GEMV | `gemv_q6k.spv` | **RELATED** | CEBA0DE4 product default SOLO+MULTI; host×SPV parity OK; ≠ full CERT |
| Q4_K packed GEMV | `gemv_q4k.spv` | **RELATED** | TinyLlama CEBA0DE4 `Q4K_PACKED_OPS=3618`; ≠ multifamily CERT |
| Q4_K WQ AVX dualpipe | `gemv_q4k_wq_close010.spv` | **PARTIAL** | SOURCE_WIRED WQ-only; tip shape matrix NOT_RUN this lane |
| Q4_K fused / oproj / kva | `gemv_q4k_{fused,oproj,kva}.spv` | **OPEN / NOT_RUN** | SOURCE_WIRED (`vulkan_fwd_q4k_fused`); isolated tip remasure absent |
| Q4_K QKV sx 32/64/128/256 | `gemv_q4k_qkv_sx_*.spv` | **OPEN / NOT_RUN** | SOURCE_WIRED sx selector; no tip shape-pack measure |
| Q8_0 packed GEMV | `gemv_q8.spv` | **NOT_RUN** | Pipeline wired (type=8); no Q8_0 weight GGUF in `models/` |
| Q8_0 KVA / sx64 | `gemv_q8_kva*.spv` | **OPEN / NOT_RUN** | SOURCE_WIRED; tip remasure absent |
| Q5_K packed GEMV | `gemv_q5k.spv` | **NOT_RUN** | Wired; no Q5_K model exercised this lane |
| Q3_K packed GEMV | `gemv_q3k.spv` | **NOT_RUN** | Wired; no Q3_K model exercised this lane |
| Q2_K packed GEMV | `gemv_q2k.spv` | **MEASURED_ABORT** | gemma3-1b-Q2_K CEBA0DE4: finite L0–L25 then EXIT=-1; TOK=0; ≠ PASS |
| Host Q6×Q8_K GEMV | QuantKernelRegistry | **RELATED** | Opt-out / parity authority; host ≠ GPU CERT |
| Ornith packed GEMV L3 | host Q4/Q6×Q8_K | **RELATED** | ULP_CLOSED vs f32 oracle R104; shapes/batches beyond L3 OPEN |
| Packed GEMM (batch>1) | — | **OPEN / NOT_RUN** | No tip batch matrix sealed |
| Full shader-family CERT | all above | **OPEN** | Do not invent CERT; PROMOTE=0 |

## Board map

- W02 Deep2 Vulkan → PARTIAL (Q6K RELATED retained; multifamily OPEN)
- W03 Q4/Q6/Q8 → PARTIAL (Q4/Q6 RELATED; Q8/Q5/Q3 NOT_RUN; Q2 MEASURED_ABORT)
- W04 Packed GEMV/GEMM → PARTIAL (Ornith L3 RELATED; specialized/batch OPEN; Q2 abort blocker)
