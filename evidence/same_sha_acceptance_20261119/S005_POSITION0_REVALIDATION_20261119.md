# S005 position-0 revalidation

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py `
  --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace `
  --ref evidence/same_sha_acceptance_20261119/ref `
  --position 0 --cos-tol 0.9999 `
  --out evidence/same_sha_acceptance_20261119/first_divergence_pos0_replay.json
```

Observed exit: `0`.

Both backends contained 395 records; 363 boundaries were comparable. Neither
backend crossed the configured cosine threshold of `0.9999`.

| Backend | Comparable | Minimum cosine | Maximum absolute error | Worst operation |
|---|---:|---:|---:|---|
| CPU | 363 | 0.9999768884826666 | 0.2266697883605957 | block 27 `ffn_out` (op 391) |
| GPU | 363 | 0.9999999998099849 | 0.001220703125 | block 26 `resid2` (op 378) |

This is a bounded position-0 diagnostic pass, not strict parity. `attn_proj`
and other unmapped boundaries remain excluded from the comparable count.

```ini
S005=BOUNDED_PASS
FIRST_THRESHOLD_CROSSING_CPU=NONE
FIRST_THRESHOLD_CROSSING_GPU=NONE
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
