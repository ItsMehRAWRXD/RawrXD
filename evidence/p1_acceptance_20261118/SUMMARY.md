# P1 acceptance matrix

Tested source SHA: `fc1ac0c855fb6b7222e86274f847b0d73ad9f83f`

## Results

```ini
FOCUSED_GPU_BUILD=PASS
REAP_ZERO_MLA_EXECUTABLE_SHA256=6E973D62CC377CC2E11C9DC7F86F8D5498ABED2F0E798EBC7E8A3471261749F2
QWEN35_GPU_CERTIFY_EXECUTABLE_SHA256=D7AAF98B01E749976D6EDF7692B5BA84F1F76A8CA05FB3A4A33FCED507F11F04

REAP_ZERO_MLA_RUN_1=PASS
REAP_ZERO_MLA_RUN_2=PASS
REAP_ZERO_MLA_RUN_3=PASS
REAP_ZERO_MLA_MAX_ABS=2.98023224e-8
REAP_ZERO_MLA_REPEATED=PASS

QWEN35_REAL_GPU_EXECUTION=PASS
QWEN35_GPU_CALLS=546
QWEN35_CPU_FALLBACK_CALLS=0
QWEN35_FINITE_LOGITS=248320/248320
QWEN35_INTERNAL_PARITY=FAIL
QWEN35_POSITION0_COSINE=0.9984229
QWEN35_POSITION0_MAX_ABS=1.072
QWEN35_POSITION1_COSINE=0.9000067
QWEN35_POSITION1_MAX_ABS=6.842

INDEPENDENT_LLAMA_REFERENCE=CAPTURED
INDEPENDENT_FULL_LOGIT_PARITY=FAIL
FUSED_LATENT_KV_MLA=NOT_EXERCISED
GPU_MOE_ROUTING_EXPERT_PARITY=NOT_ESTABLISHED
```

## Build qualification

`rawrxd_gpu_compute` and `reap_zero_mla_test` rebuilt successfully. The broader `deep2_gpu_certify` source target remains blocked by unrelated pre-existing edits in `tools/deep2_gpu_certify.cpp` (`anonymous-namespace::std` filesystem/string errors). The prebuilt executable was run only as an execution artifact and is not treated as a clean-build result.

The retained Qwen3.5 log shows real GPU execution and zero runtime CPU fallbacks, but the numerical and independent-reference gates remain open. Fused latent-KV MLA was not claimed from the explicit sequence-major REAP-ZERO tile.
