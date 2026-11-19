# Comparator structural exit semantics

```ini
SOURCE_SHA=bf14b76d89949c51da57e3d4c35f8e76f22ecbd9
COMMAND=py -3 evidence/same_sha_acceptance_20261119/compare_full_logits.py --deep2 evidence/same_sha_acceptance_20261119/deep2_logits.bin --ref evidence/same_sha_acceptance_20261119/llama_ref_full --out evidence/same_sha_acceptance_20261119/three_token_parity_rerun.json
EXIT=5
DEEP2_ROWS=5
REFERENCE_ROWS=3
POSITIONS_COMPARED=3
```

The retained llama reference uses the supported flat `ref_logits_pos<N>.bin` layout. The comparator now reads that layout and returns exit `5` only when the number of Deep2 and reference rows differs. The observed artifacts are structurally mismatched and are not a parity PASS.

Observed comparison summary: `min_cosine=0.3790832349871181`, `max_abs_worst=23.724616050720215`, `argmax_exact_positions=1`, all values finite.
