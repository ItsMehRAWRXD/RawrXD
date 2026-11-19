# S005 position-0 full operation comparison

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace --ref evidence/same_sha_acceptance_20261119/ref --position 0 --cos-tol 0.9999 --out evidence/same_sha_acceptance_20261119/first_divergence_pos0.json
```

Exit: `0`.

## Results

Both CPU and GPU traces contained 395 operation records, with 363 comparable boundaries. At the configured cosine threshold `0.9999`, neither backend had a first divergent operation.

| Backend | Compared | Minimum cosine | Maximum absolute error | Worst op | Maximum RMS |
|---|---:|---:|---:|---:|---:|
| CPU | 363 | 0.9999768884826666 | 0.2266697883605957 | 391 | 0.0537382687454988 |
| GPU | 363 | 0.9999999998099849 | 0.001220703125 | 378 | 0.0000645570526818 |

The result is a bounded position-0 operation-level pass at `cos_tol=0.9999`; it is not strict bitwise parity. `attn_proj` remains a missing reference boundary and is excluded from the comparable count.

```ini
POSITION=0
OP_RECORDS=395
COMPARED=363
CPU_FIRST_DIVERGENCE=NONE_AT_0.9999
GPU_FIRST_DIVERGENCE=NONE_AT_0.9999
GPU_MIN_COSINE=0.9999999998099849
GPU_MAX_ABS=0.001220703125
BOUNDED_POSITION0_ACCEPTANCE=PASS
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
