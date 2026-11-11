# EXT_LOAD_001 — tip 272199BE results

ASOF_UTC=2026-11-09T08:40:00Z
DISPOSITION=TIP_BUILT_EXT_LOAD_NOT_RUN
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe
TIP_SHA=272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
FROZEN_A4F_UNTOUCHED=1
EXT_LOAD=NOT_RUN
LAUNCH=PASS
BUILD_ALONE_NE_EXT_PASS=1
STARTUP_ALONE_NE_EXT_LOAD_PASS=1
```

## Independent assertions

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| 1 | Startup / HWND | **PASS** | `EXT_SMOKE_RECEIPT.md` · `logs\ext_smoke_run_20261109-034019.txt` |
| 2 | VSIX discovery | **NOT_RUN** | no invokable load/discover surface (`installExtension` placeholder; EXT objs unreferenced) |
| 3 | Activation | **NOT_RUN** | blocked by #2 |
| 4 | API / commands | **NOT_RUN** | blocked by #2 |
| 5 | Lifecycle exit | **PASS** | `EXIT_CODE=0` |
| 6 | Fault isolation | **NOT_RUN** | no load path to fault |
| 7 | Regression (editor/chat/cancel) | **NOT_RUN** | deferred to oneshot Track C |

```
EXT_LOAD=NOT_RUN
WORKER=[EXT load smoke tip_ext_host](83c36748-5687-4b8e-8dd2-4822ee18e449)
NEXT=wire product path to JSExtensionHost::initialize + loadVSIX on tip lane → re-run gates 2–4,6
```
