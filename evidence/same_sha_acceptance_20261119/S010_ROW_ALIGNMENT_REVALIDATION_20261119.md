# S010 row-alignment revalidation

The retained packed artifacts were compared with the existing comparator.

```powershell
py -3 evidence/same_sha_acceptance_20261119/compare_full_logits.py `
  --deep2 evidence/same_sha_acceptance_20261119/deep2_logits.bin `
  --ref evidence/same_sha_acceptance_20261119/llama_ref_full `
  --out evidence/same_sha_acceptance_20261119/three_token_parity_s002_replay.json
```

Observed exit: `5` with `deep2_rows=5` and `reference_rows=3`. The comparator
paired only the first three rows and reported them diagnostically. This is a
structural artifact mismatch, not a strict parity result.

```ini
S010=BLOCKED_ROW_COUNT_MISMATCH
DEEP2_ROWS=5
REFERENCE_ROWS=3
PAIRED_ROWS=3
STRICT_PARITY=NOT_CERTIFIED
MATCHING_TOKEN_COUNT_REFERENCE_REQUIRED=YES
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
