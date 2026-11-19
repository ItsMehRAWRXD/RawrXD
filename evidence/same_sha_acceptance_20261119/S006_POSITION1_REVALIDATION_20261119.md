# S006 position-1 revalidation

The pinned comparison was rerun with cosine threshold `0.9999` and exited `0`.
Both backends supplied 395 operation records and 363 comparable boundaries.

| Backend | First threshold crossing | Cosine at crossing |
|---|---|---:|
| CPU | block 2 `v`, op 33 | 0.99987098758696 |
| GPU | block 24 `swiglu`, op 348 | 0.9998787789744598 |

The CPU path diverges earlier than the GPU threshold crossing. The GPU crossing
at block 24 is therefore not proof that `swiglu` is the causal defect; upstream
error may have accumulated below the threshold. No kernel was changed.

```ini
S006=COMPARISON_REPRODUCED
OP_RECORDS=395
COMPARABLE=363
CPU_FIRST=BLOCK2_V_OP33
GPU_FIRST_THRESHOLD=BLOCK24_SWIGLU_OP348
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
