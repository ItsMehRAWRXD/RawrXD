# S010 strict full-logit row alignment

Command:

```powershell
py -3 evidence/same_sha_acceptance_20261119/compare_full_logits.py --deep2 evidence/same_sha_acceptance_20261119/deep2_logits.bin --ref evidence/same_sha_acceptance_20261119/llama_ref_full
```

Observed exit: `5`.

The comparator rejected the artifacts before treating the comparison as complete because the Deep2 binary contains 5 logit rows while the retained llama.cpp reference contains 3 rows. The comparator emitted `row count mismatch deep2=5 ref=3` and compared only the first 3 paired rows for diagnostic output.

```ini
DEEP2_LOGITS_SHA256=A5B463F94B2EEDA7020E8620DC86D816770315E1708B6908585ED5270C81DE5D
REFERENCE_SET=llama_ref_full
DEEP2_ROWS=5
REFERENCE_ROWS=3
STRUCTURAL_ALIGNMENT=FAIL
STRICT_FULL_LOGIT_PARITY=NOT_CERTIFIED
MATCHING_TOKEN_COUNT_RERUN=REQUIRED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

No numerical result from this mismatched artifact pair is promoted as strict parity evidence.
