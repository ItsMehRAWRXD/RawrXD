# T05 formal cancel evidence — SHA-bound (NON-CONTROLLING)

ASOF_UTC=2026-11-09T07:20:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
AUTHORITY=SUPERSEDED_BY_TIP_A4F083DF

```
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
SHA-256=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
SIZE=2592256
SHA_MATCH=1
MODEL=Local models / Ollama / gemma3:4b
T05=PASS_CANCEL_A_STOP_B
CONTROLLING=0
NOTE=Harness green on gemma3 does not remove Stop→COMCTL race; tip A4F083DF has drainCancelledInferenceWorker.
SEE=T05_TIP_A4F083DF_AUTHORITY.md
```

## Runs (same SHA)

| Stamp | CORR_ID | MARKER_A | MARKER_B | A | STOP | B | LATE_A | CORR |
|-------|---------|----------|----------|---|------|---|--------|------|
| 20261109-020615 | CORR_20261109-020615 | T05_A_CORR_4c616d762d | T05_B_PONG_e905fe79 | PASS | PASS | PASS | PASS | PASS |
| 20261109-020716 | CORR_20261109-020716 | T05_A_CORR_f8aa521ad1 | T05_B_PONG_b99be978 | PASS | PASS | PASS | PASS | PASS |

Receipts: `T05_A_STOP_B_RESULT_<stamp>.txt` · runlogs alongside.

## Stale Request A check (020716 re-verified)

| Check | Result |
|-------|--------|
| Stop status text | `Chat generation stopped.` |
| `[stopped] generation cancelled` in buffer before B | present |
| MARKER_A in before_b / after_b / late | **absent** (A cancelled before tokens) |
| MARKER_B in after_b / late | **present** |
| Process survived through B | yes (REQUEST_B_RENDERED; no CRASH_B) |

## Separated: unbound transcript marker

```
RAWRXD_CANCEL_RECOVERY_OK = OBSERVED_IN_UI_TRANSCRIPT
EXE_SHA_FOR_THAT_TRANSCRIPT = UNBOUND
≠ T05_FORMAL_PASS seal above
```

Prior `9C91` FAIL (`20261109-014649`) used model `bigdaddyg-productivity-local` and crashed on Request B (`exit=-1`). Controlling formal T05 for daily-driver close is the gemma3:4b SHA-bound pair above — not the unbound recovery string.

## Law

```
TRANSCRIPT_MARKER ≠ T05_PASS
T05_PASS ≠ DAILY_DRIVER_ACCEPTANCE
T05_PASS ≠ PROMOTE
FINISH_25_HISTORICAL_19/25 ≠ 9C91 acceptance score
```
