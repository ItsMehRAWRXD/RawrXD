# S007 position-2 revalidation

The pinned comparison was rerun with cosine threshold `0.9999` and exited `0`.
Both backends supplied 395 operation records and 363 comparable boundaries.

| Backend | First threshold crossing | Cosine at crossing |
|---|---|---:|
| CPU | block 2 `attn_out`, op 34 | 0.9998488579467929 |
| GPU | block 2 `ffn_out`, op 41 | 0.9998354046600886 |

Position 2 crosses the diagnostic threshold in block 2 for both paths. This
locates the earliest reported threshold crossing but does not prove either
operation is the causal defect; same-input upstream bisection remains required.

```ini
S007=COMPARISON_REPRODUCED
OP_RECORDS=395
COMPARABLE=363
CPU_FIRST=BLOCK2_ATTN_OUT_OP34
GPU_FIRST=BLOCK2_FFN_OUT_OP41
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
