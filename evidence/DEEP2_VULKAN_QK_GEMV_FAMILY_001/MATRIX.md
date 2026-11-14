# DEEP2_VULKAN_QK_GEMV_FAMILY_001 — Family matrix

```text
PROMOTE=0 CERTIFIED=0 GATE_STOP=1 TIP_CLIMB=HOLD
CROSS_SHA_CREDIT=0 INVENT_PASS=0
HIDDEN_HOST_FALLBACK ≠ Vulkan PASS
```

| ID | Family / lane | Shape / batch | Path | Status | Evidence |
|----|---------------|---------------|------|--------|----------|
| F01 | Q6_K FORCE_SPV product | TinyLlama SOLO decode | gemv_q6k.spv | **ARTIFACT_PASS** on CEBA0DE4 (exact SHA) | `Q6K_VULKAN_SPV_REPAIR_001` + commit `37d8dc32cb` |
| F02 | Q6_K default SPV | TinyLlama SOLO+MULTI | gemv_q6k.spv | **RELATED** sister | `POST_Q6K_SPV_PRODUCT_DEFAULT_001` |
| F03 | Q6_K attn_v host↔SPV | 256×2048 L0 v_proj | DispatchGEMVQuant(14) | **PARITY_OK** RELATED | `runs/deep2_gpu_q6k_gemv_cert.out.txt` maxAbs=1.86e-9 |
| F04 | Q4_K packed GEMV shapes | 2048×2048, 256×2048, 5632×2048 | DispatchGEMVPacked | **NUMERIC_OK / GATE_FAIL** | `runs/deep2_gpu_q4k_gemv_cert.out.txt` (tps=0.256) |
| F05 | Q4_K product packed ops | TinyLlama FORCE_SPV CEBA | GPU forward | **RELATED** | Q4K_PACKED_OPS=3618 HOST=0 |
| F06 | Q6_K product packed ops | TinyLlama FORCE_SPV CEBA | GPU forward | **RELATED** | Q6K_PACKED_OPS=548 HOST=0 |
| F07 | Q8_0 GEMV shapes | 64×256, 256×256, 256×2048, 2048×256 | DispatchGEMVQuant(8) | **PASS** | `runs/deep2_gpu_quant_family_cert.out.txt` |
| F08 | Q5_K / Q3_K / Q2_K | 64×256 synthetic | DispatchGEMVQuant | **PASS** (side) | same family cert |
| F09 | Packed GEMM multi-batch | broader B>1 | — | **OPEN** | not measured |
| F10 | Live tip FORCE_SPV | tip ≠ CEBA | product | **NOT_RUN / INCOMPLETE** | tip churn; CROSS_SHA=0 |
| F11 | Host fallback credited as Vulkan | any | host GEMV | **REJECT** | CEBA HOST_HITS=0; law held |

## Aggregate
```text
WS3=RELATED
FAMILY_CERTIFIED=0
ANY_HOST_FALLBACK_AS_VULKAN_PASS=0
NEXT=Q4K_split_numeric_vs_tps | tip FORCE_SPV remasure | GEMM batch matrix
```
