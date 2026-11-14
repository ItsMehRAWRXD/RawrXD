# W5 DEEP2_VULKAN_KERNEL_FAMILIES — Kernel Matrix

```text
PROMOTE=0 CERTIFIED=0 ENTERPRISE=0/128
INVENT_PASS=0 CROSS_SHA_CREDIT=0 TIP_CLIMB=HOLD GATE_STOP=1
NO_REABSORB=R103|R104
PROGRAM=RAWRXD_ALL_BACKENDS_COMPLETE_001
EXE_SHA256=4743825156D9B012EDBB4F28F8249F2730A6B816BD6538B1FA82BCEA8754633D
PRIOR_R104_CEBA0DE4=HELD (CROSS_SHA=0; remasured tip this pack)
PRIOR_R103_E7797EE8=HELD
```

| Family | Kernel / path | Shapes exercised | SPV↔host | Product default | Status |
|--------|---------------|------------------|----------|-----------------|--------|
| Q6_K GEMV | gemv_q6k.spv | attn_v 256x2048 | PARITY_OK maxAbs=1.86e-9 maxULP=640 | unforced; HOST_HITS=0 | PASS_MEASURED |
| Q4_K packed GEMV | DispatchGEMVPacked / gemv_q4k.spv | 2048x2048, 256x2048, 5632x2048 (L0 q/k/v/o + FFN) | maxAbs<=2.97e-3 rms<=6.3e-4 | packed ops=2958; FALLBACK=0 | PASS_MEASURED |
| Q8_0 GEMV | gemv_q8.spv | 64x256, 256x256, 256x2048, 2048x256 | maxAbs<=3.05e-5 | synthetic shape expand | PASS_MEASURED |
| Q5_K / Q3_K / Q2_K | family SPV | 64x256 baseline | PASS | — | PASS_MEASURED |
| Attn / KV (TinyLlama) | v_proj / k_proj product path | short-ctx decode TOK=8 | v_proj L0 finite=256/256 | COHERENT=1 | PASS_MEASURED |
| Packed GEMM batches | — | broader batch matrix | — | — | OPEN |
| Long-context KV | — | — | — | — | OPEN |
| Multifamily Q6_K V | — | — | — | — | HOLD |

## R105 gates (this pack)

| Gate | Result |
|------|--------|
| Q6K_PRODUCT_DEFAULT (unforced; no host fallback as cert) | PASS_MEASURED HOST_HITS=0 |
| Q6K_SPV_NUMERIC (independent SPV↔host) | PASS_MEASURED PARITY_OK |
| Q4/Q8 + GEMV shape expand | PASS_MEASURED |
| R103/R104 preserve | HELD NO_REABSORB |

## Honest limits

- HOST_FALLBACK != SPV_CERT (FORCE_HOST control remains diagnostic-only).
- TinyLlama lane only; multifamily HOLD.
- PROMOTE=0 · != enterprise CERT PASS.
