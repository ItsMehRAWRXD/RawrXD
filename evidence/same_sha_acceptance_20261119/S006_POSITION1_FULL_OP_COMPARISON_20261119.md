# S006 position-1 full operation comparison

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace --ref evidence/same_sha_acceptance_20261119/ref --position 1 --cos-tol 0.9999 --out evidence/same_sha_acceptance_20261119/first_divergence_pos1.json
```

Exit: `0`.

Both backends provided 395 operation records and 363 comparable boundaries.

| Backend | First divergence | Cosine | Minimum cosine | Maximum absolute error | Worst op | Maximum RMS |
|---|---|---:|---:|---:|---:|---:|
| CPU | block 2 `v`, op 33 | 0.99987098758696 | 0.9959676982664701 | 1.2904281616210938 | 392 | 0.18271973331272143 |
| GPU | block 24 `swiglu`, op 348 | 0.9998787789744598 | 0.9994992492311074 | 0.7625083923339844 | 390 | 0.10456383322577655 |

The first CPU threshold crossing occurs before the attention output at block 2. The GPU path remains above the threshold until block 24, where the accumulated trace crosses at `swiglu`. This is a diagnostic result, not a kernel attribution or strict parity pass.

```ini
POSITION=1
OP_RECORDS=395
COMPARED=363
CPU_FIRST_DIVERGENCE=BLOCK2_V_OP33
GPU_FIRST_DIVERGENCE=BLOCK24_SWIGLU_OP348
REFERENCE_VARIANTS=MAPPED_S004
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
