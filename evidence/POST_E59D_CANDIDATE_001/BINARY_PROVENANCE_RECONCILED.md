# Binary Provenance Reconciled

ASOF_UTC=2026-11-09T07:17:00Z
STATUS=RECONCILED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
T05_FORMAL_PASS=NOT_ESTABLISHED

## Lineages (must not inherit PASS across SHAs)

| SHA prefix | Role | Disposition |
|------------|------|-------------|
| `71D14597…` | Build-path tip / 71D package (doc-tab max+stuck-tab tip) | SEPARATE candidate |
| `3B720981…` | Historical T24 package payload | Baseline evidence only |
| `9C910599…` | DAILY_DRIVER frozen candidate | Restored for sealed retests; provenance = package restore, not active build dir |
| `0F054F01…` | build_ide Native tip (max-steps handoff) | SEPARATE candidate — do not conflate |

## Law

```
BINARY_PROVENANCE=RECONCILED
71D_TIP=SEPARATE
T24_BASELINE=3B720981
DAILY_DRIVER_FREEZE=9C910599
BUILD_IDE_0F054F01=SEPARATE
T24_PACKAGE ≠ CERTIFY(71D|9C91|0F05)
PASS(SHA_A) ≠ PASS(SHA_B)
ABSENCE_FROM_BUILD_DIR ≠ INVALIDATE_SEALED_RETESTS
CANCEL_MARKER_TRANSCRIPT ≠ T05_PASS_UNTIL_SHA_BOUND
```

## Marker bind (this turn)

```
MARKER_SHA=0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E
BIND_SEAL=MARKER_SHA_0F054F01.md
T05_ON_MARKER_SHA=FAIL_AGGREGATE  # ≠ invent PASS; ≠ inherit 9C91 T05
A4F083DF_021702_BUFFER=STALE_UI_LEFTOVER_NOT_MARKER_PRODUCER
```

## Next

1. Keep `9C910599…` as reference for its existing sealed retests (T05/T07/T10/T17 PASS; T08 FAIL MAIN_LOST).
2. `RAWRXD_CANCEL_RECOVERY_OK` bound to `0F054F01…` — formal T05 credit still NOT_ESTABLISHED (boards FAIL).
3. Select **one** candidate for the next complete daily-driver acceptance run (prefer freeze after T08 clears, or explicitly authorize switch).
