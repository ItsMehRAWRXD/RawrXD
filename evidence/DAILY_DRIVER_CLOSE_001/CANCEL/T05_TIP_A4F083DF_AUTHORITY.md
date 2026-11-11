# T05 tip authority after Request B crash fix

ASOF_UTC=2026-11-09T07:20:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
CONTROLLING_T05_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe
TIP_SIZE=2601472
BUILD_MIRROR=F:\rawrxd\build_repair_finish25\bin\RawrXD-Win32IDE-Native.exe
T05=PASS_CANCEL_A_STOP_B
RECEIPT=T05_A_STOP_B_RESULT_20261109-021702.txt
ROOT_CAUSE=T05_CRASH_ROOT_CAUSE_20261109-021702.md
WORKER=[T05 Request B crash](364c695f-0e4e-429b-b18e-7fb869c6097f)
```

## Frozen package (untouched)

```
FROZEN_PACKAGE_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
FROZEN_PACKAGE_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
FROZEN_T05_CANCEL_RACE=STILL_VULNERABLE  # no drainCancelledInferenceWorker
```

## Authority law

```
TIP_T05_PASS ≠ FROZEN_PACKAGE_REWRITE
9C91_GEMMA_HARNESS_PASS ≠ PRODUCT_FIX   # race may miss COMCTL flush window
PRODUCT_FIX = drainCancelledInferenceWorker before discovery flush
DAILY_DRIVER_ACCEPTANCE=FAIL until editor+T16+ext+T18/T19 on CONTROLLING tip SHA
PROMOTE=0
```

## Product fix (source)

- `Win32IDE::drainCancelledInferenceWorker()`
- `HandleCopilotStop` drains before `flushDeferredModelDiscoveryIfIdle`
- Stream generation fence; join without holding `m_inferenceMutex`
