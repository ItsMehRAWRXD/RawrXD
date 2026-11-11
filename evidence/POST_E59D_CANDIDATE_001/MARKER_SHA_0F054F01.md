# MARKER_SHA bind — RAWRXD_CANCEL_RECOVERY_OK

ASOF_UTC=2026-11-09T08:47:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
T05_FORMAL_PASS=ESTABLISHED_ON_MARKER_SHA

```
MARKER_TEXT=RAWRXD_CANCEL_RECOVERY_OK
STOP_FEEDBACK=[stopped] generation cancelled
MARKER_SHA=0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E
EXE=F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe
EXE_SIZE=1484800
BIND_STATUS=BOUND
PRODUCER=tools\uia\T05_Cancellation_Recovery.ps1
CONTROLLING_BOARD=F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006
T05_SEAL=F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\T05_FORMAL_PASS_0F054F01.md
CHAT_RUNTIME=F:\rawrxd\build_ide\bin\chat_runtime.log
```

## Bind rationale (fail-closed)

1. Only `T05_Cancellation_Recovery.ps1` injects the exact strings
   `Generate a very long detailed response about C++ build systems…` and
   `Reply exactly: RAWRXD_CANCEL_RECOVERY_OK`.
2. Controlling board `_006` asserted candidate SHA via `Assert-RawrCandidate` against
   `0F054F01…` on every trial (`CandidateSHA256` / pre/post board hash match).
3. All five trials: CancelObserved + SecondRequestRecovered (exact AI marker) +
   ProcessAlive; StaleA reject proven (incl. trial 5 `stale_ui_update rendered=0`).
4. Prior `_001`/`_002` remain historical FAIL boards; disposition superseded by `_006`.

## Explicit non-binds (no cross-SHA inheritance)

| SHA | Role | Marker credit |
|-----|------|---------------|
| `9C910599…` | DAILY_DRIVER freeze | **NO** — freeze T05 uses `T05_B_PONG_*` / `T05_A_CORR_*` |
| `71D14597…` | tip | **NO** |
| `3B720981…` | T24 baseline | **NO** |
| `A4F083DF…` | repair tip | **NO** |

## Law

```
MARKER_SHA=0F054F01
T05_ON_0F054F01=PASS_AGGREGATE_006
PASS(9C91) ≠ PASS(0F054F01)
PASS(0F054F01) ≠ PROMOTE
T08_MAIN_LOST = FREEZE_SIBLING (do not steal)
NO_CROSS_SHA_PASS_INHERITANCE=1
NOT_RUN ≠ PASS
PROMOTE=0
```
