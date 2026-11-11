# T05 Marker Absorbed — SHA-scoped PASS (user-accepted)

ASOF_UTC=2026-11-09T08:56:00Z
PROMOTE=0
CERTIFIED=0
STOP_CONDITION=NOT_MET

```
T05_ON_MARKER_SHA=PASS
MARKER_SHA=0F054F01…
BOARD=BUILD_IDE_0F054F01_T05_006
SEAL=POST_E59D_CANDIDATE_001/T05_FORMAL_PASS_0F054F01.md
NO_CROSS_SHA_PASS_INHERITANCE=1
ONESHOT_ABSORPTION=RECORDED
FINISH25_HISTORICAL=19/25
ONESHOT_B_TO_F=IN_PROGRESS
```

## Law

```
PASS(0F054F01) ≠ PASS(freeze 9C91)
PASS(0F054F01) ≠ PASS(EXT tip)
PASS(0F054F01) ≠ PASS(future integrated candidate)
PASS(0F054F01) ≠ FINISH25_ADVANCE
PASS(0F054F01) ≠ PROMOTE
```

Do not restart completed discovery or re-run T05 on the marker unless the marker binary changes.
When an integrated candidate exists, rerun T05 against that candidate's exact SHA and seal independently.
