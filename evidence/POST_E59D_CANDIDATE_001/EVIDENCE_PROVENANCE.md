# Evidence Provenance — Finish-25 reconstruction note

ASOF_UTC=2026-11-08T22:48:00Z
BASELINE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F

## Law

```
RECONSTRUCTED_RECEIPT != ORIGINAL_BASELINE_ARTIFACT
DOCUMENTATION_RECOVERY != ADDITIONAL_ACCEPTANCE_PASS
```

- Preserve original dumps, workdirs, and historical `NEXT_ACTION` lineage.
- Identify rewritten receipts by creation time / retest provenance (e.g. `RETEST_T17_T07_T08_T10_*`, `CRASH_ORIGIN_REQUEST_A_20261108`).
- Every acceptance receipt must carry full active EXE SHA-256.
- Distinguish recovered evidence from previously sealed evidence (Git `b46fb5f4f9` + later additive).

## Authoritative Finish-25 (post T24 credit)

```
FINISH_25_PASS=19
FINISH_25_REMAINING=6
T17=PASS
T10=PASS
T07=FAIL
T08=FAIL
T24=CANDIDATE_PACKAGE_PASS
T15_EDIT_CONTENT=FAIL_ISOLATED
T15_TIMEOUT=PASS
PRODUCT_DEFECT_T15=NOT_PROVEN
ROOT_CAUSE=MODEL_EDIT_ARGS_PARTIAL_OR_MANGLED
PRODUCT_DEFECT_T07_T08=PROVEN
BATCH1=FAIL
REBUILD_AUTHORIZED=1
PROMOTE=0
CERTIFIED=0
```

Remaining 6: T05 · T07 · T08 · T18 · T19 · T25 (repair candidate in flight).
18/25 was pre-T24; **19/25** is controlling after T24 candidate-package PASS.
