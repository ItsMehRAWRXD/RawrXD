# T05 formal cancel-recovery — MARKER_SHA only

ASOF_UTC=2026-11-09T08:47:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
T25=HELD
NO_CROSS_SHA_PASS_INHERITANCE=1

```
MARKER_SHA=0F054F01380BA745F760A973E894A6809BBD777FCA871108CDC61AB029CA2F8E
EXE=F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe
EXE_SIZE=1484800
SHA_MATCH=1
MODEL=Local models / Ollama / gemma3:4b
MARKER_TEXT=RAWRXD_CANCEL_RECOVERY_OK
BOARD=F:\rawrxd\evidence\BUILD_IDE_0F054F01_T05_006
T05_CRITERIA=5/5
COMBINED_STALE_A=5/5
AggregateDisposition=PASS
T05_FORMAL_PASS=ESTABLISHED_ON_MARKER_SHA
T05_ON_MARKER_SHA=PASS
```

## Five-trial matrix (controlling)

| Trial | Cancel | Sent B | Recovered | Alive | T05 | StaleA | Combined |
|------:|:------:|:------:|:---------:|:----:|:---:|:------:|:--------:|
| 1 | Y | Y | Y | Y | PASS | PASS | PASS |
| 2 | Y | Y | Y | Y | PASS | PASS | PASS |
| 3 | Y | Y | Y | Y | PASS | PASS | PASS |
| 4 | Y | Y | Y | Y | PASS | PASS | PASS |
| 5 | Y | Y | Y | Y | PASS | PASS | PASS |

Trial 5 chat delta includes `stale_ui_update request_id=1 rendered=0` — counted as
**reject proof**, not late rendered A (harness rescore; see aggregate `Rescore`).

## Explicit non-inheritance

| SHA | Role | Credit |
|-----|------|--------|
| `9C910599…` | DAILY_DRIVER freeze T05=PASS | **NO** — separate seal / markers |
| `A4F083DF…` | tip drainCancelledInferenceWorker | **NO** |
| `71D14597…` | tip | **NO** |
| `3B720981…` | T24 baseline | **NO** |

```
PASS(0F054F01) ≠ PASS(9C91)
PASS(0F054F01) ≠ DAILY_DRIVER_ACCEPTANCE
PASS(0F054F01) ≠ PROMOTE
T08_MAIN_LOST = FREEZE_SIBLING_TRACK (do not steal)
NOT_RUN ≠ PASS
PROMOTE=0
```

## Prior boards (superseded for disposition)

- `BUILD_IDE_0F054F01_T05_001` FAIL 1/5
- `BUILD_IDE_0F054F01_T05_002` FAIL 3/5 criteria (StaleA unwrap false FAIL)
- `BUILD_IDE_0F054F01_T05_003`–`_005` harness iteration (STOP_NEVER_ENABLED / model wait)
- Controlling: `BUILD_IDE_0F054F01_T05_006`
