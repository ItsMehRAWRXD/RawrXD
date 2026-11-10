# HARNESS_CROSSPROC_SB_GETTEXT — proven origin (not product defect)

ASOF_UTC=2026-11-09T04:05:00Z
PACK=REQUEST_A_DIAG_001
PROMOTE=0
CERTIFIED=0
SEALED_EVIDENCE_NOREWRITE=PROGRESSION_FINISH25_001/CANCEL/*

## Verdict

```
HARNESS_CROSSPROC_SB_GETTEXT=PROVEN_ORIGIN
PRODUCT_DEFECT_CANCEL=NOT_PROVEN
GHOSTTEXT_SOLE_CAUSE=FALSIFIED (prior seal stands)
REQUEST_A_PRIOR_FAIL_EXPLAINED=HARNESS_ARTIFACT
```

## Mechanism

Request A survival harnesses polled status text via cross-process `SendMessageW` to `msctls_statusbar32`:

- `SB_GETTEXTLENGTHW` = `0x040C`
- `SB_GETTEXTW` = `0x040D`

`SB_GETTEXT*` is **not** on the Windows cross-process message marshal list (unlike `WM_GETTEXT` / `WM_SETTEXT`). The remote COMCTL32 v5.82 handler treats `lParam` as an in-process pointer and executes `mov word ptr [rcx], ax` at **COMCTL32.dll+0xBD02**, writing into invalid guest memory → `EXIT 0xC000041D`, `R12=0x40D`.

This matches sealed exception context (`R12=0x40D`, `RBP=0xF000`, `RDX=0xFFFF`) without requiring an IDE control-lifetime defect.

## On-disk candidate at fix time

```
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
SHA256=18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68
SIZE=2509824
LOCKED_4ED_ON_DISK=0
```

## Harness repair (this pack)

1. Remove cross-process `SB_GETTEXT*` from all `harness_request_a_survival*.ps1`.
2. Optional status log: `WM_GETTEXTLENGTH` (`0x000E`) + `WM_GETTEXT` (`0x000D`) only.
3. Arming may use stop-button enabled; status regex only after WM_GETTEXT fix.

## Law

```
HARNESS_FAULT ≠ PRODUCT_PASS
NOT_RUN ≠ PASS
DIAGNOSTIC_INSTRUMENTATION ≠ ACCEPTANCE_PASS
```
