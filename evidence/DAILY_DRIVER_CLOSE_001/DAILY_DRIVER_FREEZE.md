# DAILY_DRIVER_FREEZE — A4F083DF (slim profile)

ASOF_UTC=2026-11-09T07:37:47Z

```
SHA256=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
SIZE=2601472
EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
TIP_SOURCE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe
BAK_9C91=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe.9C910599.bak
BAK_18FA=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe.18FA04F9.bak
PROFILE=SLIM_WIN32IDE_NATIVE
EXT=OUT_OF_SCOPE
SLIM_DAILY_DRIVER_ACCEPTANCE=PASS
FULL_FEATURE_DAILY_DRIVER=FAIL
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
FINISH_25_HISTORICAL=19/25
FINISH_25_NE_REWRITTEN=1
```

## Slim conjunction closed on this SHA

T05 · T07 · T08 · T10 · T17 · T16 · T18 · T19 — PASS  
EXT — OUT_OF_SCOPE (`SLIM_DAILY_DRIVER_EXT_POLICY.md`) — NOT recorded as PASS

## Rollback to prior freeze (9C91)

```powershell
Copy-Item -LiteralPath 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe.9C910599.bak' `
  -Destination 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe' -Force
```

Expected: `9C910599…` SIZE=2592256 (cancel race present).

## Rollback to 18FA

```powershell
Copy-Item -LiteralPath 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe.18FA04F9.bak' `
  -Destination 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe' -Force
```

```
FREEZE ≠ PROMOTE
SLIM_ACCEPTANCE ≠ CERTIFIED
```
