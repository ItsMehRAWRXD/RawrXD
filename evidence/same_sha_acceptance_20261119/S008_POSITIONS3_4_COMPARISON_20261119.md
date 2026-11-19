# S008 positions 3–4 operation comparison

Commands used the unchanged S004 Q/K/V mapping and `cos_tol=0.9999`:

```powershell
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace --ref evidence/same_sha_acceptance_20261119/ref --position 3 --cos-tol 0.9999 --out evidence/same_sha_acceptance_20261119/first_divergence_pos3.json
py -3 evidence/same_sha_acceptance_20261119/first_divergence.py --trace-dir evidence/same_sha_acceptance_20261119/certify_qwen_1p5b/op_trace --ref evidence/same_sha_acceptance_20261119/ref --position 4 --cos-tol 0.9999 --out evidence/same_sha_acceptance_20261119/first_divergence_pos4_rerun.json
```

Both commands exited `0`; each backend had 395 records and 363 comparable boundaries.

| Position | Backend | First divergence | Cosine | Minimum cosine | Maximum absolute error | Worst op |
|---:|---|---|---:|---:|---:|---:|
| 3 | CPU | block 1 `ffn_out`, op 27 | 0.9998312460249679 | 0.9954606285269813 | 1.9608535766601562 | 391 |
| 3 | GPU | block 1 `ffn_out`, op 27 | 0.9998313483281915 | 0.9971428563958669 | 1.85577392578125 | 213 |
| 4 | CPU | block 0 `up`, op 11 | 0.9998673514384594 | 0.9936375443459973 | 2.40716552734375 | 213 |
| 4 | GPU | block 0 `up`, op 11 | 0.9998673515068542 | 0.9945344673369414 | 1.7348175048828125 | 392 |

The reported position-4 block-0 `up` crossing reproduces. The trace does not include the projection weights or a same-input replay, so it does not identify whether the cause is input propagation, weight decoding, or projection arithmetic.

```ini
POSITIONS_3_4=COMPARED
POSITION4_UP_DIVERGENCE=REPRODUCED
POSITION4_UP_WEIGHT_CAPTURE=NOT_PRESENT
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
