# Request B Origin — DAILY_DRIVER_CLOSE_001 (9C910599)

ASOF_UTC=2026-11-09T07:15:00Z
ACTIVE_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
SIZE=2592256
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_FIX_APPLIED=0

## Prior FAIL (assessment freeze)

| Stamp | SHA | Model | A | Stop | B | Notes |
|-------|-----|-------|---|------|---|-------|
| 20261109-014649 | 9C910599 | bigdaddyg-productivity-local | PASS | PASS (status empty) | CRASH exit=-1 @+2ms | exit=-1 alone ≠ root cause |
| tip 015722 | 71D14597 (≠ freeze) | gemma3:4b | PASS | PASS | CRASH @~10s | tip SEPARATE |

## Dump class (tip WER, not freeze)

```
Dump=C:\Users\Garrett\AppData\Local\CrashDumps\RawrXD-Win32IDE-Native.exe.7688.dmp
ExceptionCode=0xC0000005 (read)
FAULT=comctl32.dll (v5.82) +0x5F85C
≠ Request-A sealed class comctl32+0xBD02 write
NEW_DUMP on freeze T05 retests= (none)
```

## Live retest on freeze (repaired harness; NO SB_GETTEXT cross-proc)

| Stamp | Result | Markers |
|-------|--------|---------|
| 20261109-020615 | PASS_CANCEL_A_STOP_B | A=T05_A_CORR_4c616d762d B=T05_B_PONG_e905fe79 |
| 20261109-020716 | PASS_CANCEL_A_STOP_B | A=T05_A_CORR_f8aa521ad1 B=T05_B_PONG_b99be978 |

```
REQUEST_A=PASS
STOP=PASS (status='Chat generation stopped.')
REQUEST_B=PASS (marker rendered)
LATE_A_STALE_REJECT=PASS
CORR_OK=PASS
CANCEL_PRODUCT_DEFECT=NOT_PROVEN
→ no cancel/lifetime/generation tip fix (causality for product tip not proven on freeze)
```

## Origin verdict

```
REQUEST_B_ORIGIN=INTERMITTENT_PRIOR_CRASH_B_EXIT_NEG1
PRIOR_TIP_DUMP_CLASS=COMCTL32_V5_READ_AV_0x5F85C
FREEZE_T05_RETEST=PASS_X2
PRODUCT_TIP_FIX=NOT_APPLIED
HARNESS=NO_SB_GETTEXT_CROSSPROC (proven Request-A crash origin held)
PROMOTE=0
```
