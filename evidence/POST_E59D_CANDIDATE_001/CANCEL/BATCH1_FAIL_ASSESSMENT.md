# BATCH1 Cancel Recovery — Failure Assessment

ASOF_UTC=2026-11-03T14:30:00Z
AUTHORITY_RECEIPT=BATCH1_CANCEL_RECOVERY_RECEIPT.md

```
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SHA_MATCH=1
BATCH1_CANCEL_RECOVERY=FAIL
CRASH_SIGNATURE=REPRODUCED
CRASH_ROOT_CAUSE=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
NEXT_GATE=BATCH1_CANCEL_RECOVERY
EXECUTION_AUTHORIZATION=PENDING
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
```

Isolation remains the preferred first step *inside* BATCH1 once explicitly authorized — not a blind A→Stop→B repeat, and not authorized by this assessment alone.

## Established

- SHA unchanged; crash before A start confirmed / before Stop/B.
- Clear and dual-SetEdit not necessary for crash (simplified harness).
- `comctl32+0xBD02` = fault locus, not proven initiating cause.
- Downstream Stop/B/late-A checks blocked — not independent product failures.

## Isolation plan (no speculative rebuild)

1. Compare `092638.dmp` vs sealed `070906.dmp` / `073409.dmp` (context, stacks, threads, HWNDs).
2. Isolate single BM_CLICK vs genuine manual Send on same EXE.
3. Capture earliest failing callback / message transition.
4. Product callback proven → authorize narrow repair + new candidate cert; else harness fix + retest.
5. Resume A→Stop→B only after Request A survives.
