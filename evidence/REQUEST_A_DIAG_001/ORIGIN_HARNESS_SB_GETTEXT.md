# REQUEST_A_DIAG_001 — harness cross-process SB_GETTEXT origin

ASOF_UTC=2026-11-09T04:00:00Z
PROMOTE=0
CERTIFIED=0
SEALED_AUTHORITY_NOREWRITE=PROGRESSION_FINISH25_001/CANCEL ORIGIN/TIP_FIX/CRASH_STACK

## Proven origin

```
ORIGIN=HARNESS_CROSSPROCESS_SB_GETTEXTW
MSG=0x040D (SB_GETTEXTW) / 0x040C (SB_GETTEXTLENGTHW)
MATCH_R12=0x40D (exception_context_4ED342CE_deepened.txt)
FAULT_SITE=COMCTL32.dll 5.82 +0xBD02 mov word ptr [rcx], ax
CROSS_PROCESS_MARSHAL=NOT_SUPPORTED_FOR_SB_GETTEXT
PRODUCT_WNDPROC_REQUIRED=0
PRODUCT_DEFECT_CANCEL=NOT_PROVEN (unchanged)
GHOSTTEXT_SOLE_CAUSE=FALSIFIED (unchanged)
```

Windows marshals WM_GETTEXT/WM_SETTEXT across processes. SB_GETTEXT* (WM_USER+n) is not marshaled; receiver writes lParam as a local pointer → AV.

Harness loop (progression):
`while arm: StatusBarText(main) → SendMessageW(statusbar, 0x040D, …)` every 200ms after Request A submit.

## Fix

Replace cross-process SB_GETTEXT* with WM_GETTEXT (0x000D) / GetWindowTextW, or arm solely on Stop enabled. Rebuild of tip EXE not required for this origin class.

## Gates

```
REQUEST_A_SURVIVES=PENDING_RETEST
T05=NOT_RUN T10=NOT_RUN T07=NOT_RUN T08=NOT_RUN T17=NOT_RUN
NOT_RUN != PASS
```
