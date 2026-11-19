# S007 position-2 full operation comparison

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace --ref evidence/same_sha_acceptance_20261119/ref --position 2 --cos-tol 0.9999 --out evidence/same_sha_acceptance_20261119/first_divergence_pos2.json
```

Exit: `0`.

Both backends provided 395 operation records and 363 comparable boundaries.

| Backend | First divergence | Cosine | Minimum cosine | Maximum absolute error | Worst op | Maximum RMS |
|---|---|---:|---:|---:|---:|---:|
| CPU | block 2 `attn_out`, op 34 | 0.9998488579467929 | 0.9965431167759198 | 1.7762680053710938 | 391 | 0.17905432550255435 |
| GPU | block 2 `ffn_out`, op 41 | 0.9998354046600886 | 0.9964940239498463 | 1.4630966186523438 | 392 | 0.1765540841871639 |

The first threshold crossings are distinct between CPU and GPU. This is diagnostic evidence only; it does not establish a causal kernel defect without same-input isolation.

```ini
POSITION=2
OP_RECORDS=395
COMPARED=363
CPU_FIRST_DIVERGENCE=BLOCK2_ATTN_OUT_OP34
GPU_FIRST_DIVERGENCE=BLOCK2_FFN_OUT_OP41
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
