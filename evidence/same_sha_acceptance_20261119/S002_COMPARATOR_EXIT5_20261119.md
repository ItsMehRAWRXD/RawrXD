# S002 comparator exit semantics

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/compare_full_logits.py --deep2 evidence/same_sha_acceptance_20261119/deep2_logits.bin --ref evidence/same_sha_acceptance_20261119/llama_ref_full --out evidence/same_sha_acceptance_20261119/three_token_parity_s002.json
```

Observed exit: `5`.

The comparator source explicitly reserves exit `5` for an incomplete structural comparison. This run produced `deep2_rows=5` and `reference_rows=3`, so the exit is a row-count mismatch, not a numerical verdict. Three paired positions were compared and reported separately.

Observed metrics: `min_cosine=0.3790832349871181`, `max_abs_worst=23.724616050720215`, `argmax_exact_positions=1`, all values finite.

```ini
EXIT_5=STRUCTURAL_ROW_COUNT_MISMATCH
DEEP2_ROWS=5
REFERENCE_ROWS=3
POSITIONS_COMPARED=3
NUMERICAL_PARITY=FAIL_FOR_RETAINED_ARTIFACTS
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
