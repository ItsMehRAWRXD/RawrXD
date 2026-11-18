# WP-02 independent reference comparison

The teacher-forced reference harness was corrected to decode one token at a time and read `llama_get_logits_ith(ctx, 0)`. The previous batched `llama_get_logits` capture was not used for this result.

```ini
TOKENS=1,185
KV=F32/F32
VOCAB=248320
REFERENCE_EXIT=0
REFERENCE_LOGITS_BYTES=1986560
REFERENCE_LOGITS_SHA256=0CE824475D799E636E98F2C80AB4B9A62E8A47516D40D8CD228BA8E8168944A5
```

## Valid comparison result

```ini
CPU_POS0_MAX_ABS=11.0727121
CPU_POS0_RMS=0.04445517
CPU_POS0_COSINE=-0.1352413
CPU_POS0_ARGMAX=760
REFERENCE_POS0_ARGMAX=5328

CPU_POS1_MAX_ABS=13.3048797
CPU_POS1_RMS=0.07741185
CPU_POS1_COSINE=-0.0892910
CPU_POS1_ARGMAX=1
REFERENCE_POS1_ARGMAX=314

GPU_POS0_MAX_ABS=11.1094403
GPU_POS0_RMS=0.04900307
GPU_POS0_COSINE=-0.2484261
GPU_POS0_ARGMAX=760
GPU_POS1_MAX_ABS=12.7480426
GPU_POS1_RMS=0.05525792
GPU_POS1_COSINE=0.3438893
GPU_POS1_ARGMAX=1

WP02_REFERENCE_COMPARISON=FAIL
```

This result is evidence of a real Deep2/reference semantic mismatch. It does not identify the first divergent Deep2 operation. Numerical certification remains blocked.
