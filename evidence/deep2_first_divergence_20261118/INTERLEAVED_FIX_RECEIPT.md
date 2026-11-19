# GDN interleaved head-mapping fix

```ini
CPU_FIX=hv%Hk
VULKAN_FIX=hv%pc.key_heads
SPIRV_REBUILD=PASS
PARITY_TRACE_BUILD=PASS
MODEL=qwen3.8-27b
TOKENS=1,185
```

Layer-0 GDN attention projection now matches the retained llama.cpp reference:

| Position | Cosine | Max abs |
|---:|---:|---:|
| 0 | 0.9999999999999765 | 1.62e-7 |
| 1 | 0.9999999999996158 | 5.72e-6 |

The full trace moved the first reported divergence downstream:

```ini
POS0_FIRST_REPORTED_DIVERGENCE=BLOCK4_ATTN_PROJ
POS0_LOCAL_COS=0.999988779
POS0_LOCAL_MAX=0.00225914
POS1_FIRST_REPORTED_DIVERGENCE=BLOCK0_FFN_OUT
POS1_LOCAL_COS=0.999999371
POS1_LOCAL_MAX=0.0027639
FULL_LOGIT_PARITY=FAIL
```

The GDN head-mapping defect is corrected, but full-model parity is not yet accepted.
