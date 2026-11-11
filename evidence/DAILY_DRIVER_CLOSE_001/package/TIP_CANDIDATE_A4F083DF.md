# Tip daily-driver candidate (not promoted)

ASOF_UTC=2026-11-09T07:35:00Z

```
TIP_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe
SIZE=2601472
FROZEN_PACKAGE_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
DAILY_DRIVER_ACCEPTANCE=FAIL
FREEZE_REPLACE_9C91=HELD
```

## Closed on tip `A4F083DF…`

| Gate | Status |
|------|--------|
| T05 cancel | PASS_CANCEL_A_STOP_B |
| T17 / T07 / T08 / T10 | PASS |
| T16 compile/link/run | PASS |
| T18 bounded N=12 | PASS |
| T19 memory samples | PASS |

## Open / hold

| Gate | Status | Why |
|------|--------|-----|
| Extensions / VSIX load | **NOT_RUN** | No ExtensionHost/loadVSIX in slim tip EXE |
| Freeze replace of `9C91` | **HELD** | EXT NOT_RUN ≠ PASS |
| CERTIFIED / PROMOTE | 0 | mandatory |

```
NOT_RUN != PASS
TIP_SUITE_PARTIAL ≠ PACKAGE_PROMOTE
WORKER=[T16 ext T18 T19 tip](ebccead7-fe71-4e20-ad54-a5ab666e75f2)
```
