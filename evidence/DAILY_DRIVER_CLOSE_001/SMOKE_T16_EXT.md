# T16 / Extension smoke — DAILY_DRIVER_CLOSE_001

ASOF_UTC=2026-11-09T07:34:11Z

```
CONTROLLING_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe
MIRROR=F:\rawrxd\build_repair_finish25\bin\RawrXD-Win32IDE-Native.exe
CANDIDATE=F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe
TIP_SHA_VERIFIED=1
T16_COMPILE=PASS
T16_RUN=PASS
EXT_LOAD=NOT_RUN
PROMOTE=0
CERTIFIED=0
NOT_RUN!=PASS
```

## T16 native compile/link/run (tip lineage)

| Step | Result | Evidence |
|------|--------|----------|
| SHA pre tip/cand/finish25 | `A4F083DF…` | verified |
| `ninja RawrXD-Win32IDE-Native` in `build_repair_candidate` | **PASS** `NINJA_EXIT=0` (no work / up-to-date) | `logs\t16_ninja_20261109-023127.txt` |
| SHA post | unchanged `A4F083DF…` | same log |
| Launch tip → HWND `RawrXD_IDE_Window` → clean close | **PASS** `EXIT_CODE=0` | `logs\t16_run_20261109-023244.txt` |

Commands:

```
ninja RawrXD-Win32IDE-Native   # cwd F:\rawrxd\build_repair_candidate ; EXIT=0
Start-Process TIP_EXE          # HWND observed; WM_CLOSE; EXIT=0
```

## Extensions / ExtensionHost / VSIX

```
EXT_LOAD=NOT_RUN
MISSING_SURFACE=
  tip slim RawrXD-Win32IDE-Native.exe contains NO linked ExtensionHost / JSExtensionHost /
  loadVSIX / VSIX / QuickJS strings or objects.
PRESENT_ONLY=
  sidebar discovery list (m_hwndExtensionsList) enumerates local VS Code/Cursor extension
  roots; discovery ≠ load/activate. Repo has F:\rawrxd\extensions\* and
  rawrxd_extension_runtime, but that path is NOT wired into this tip EXE.
ATTEMPTED_LOAD_SMOKE=0  # no product load API surface on TIP_EXE to invoke
LAW=NOT_RUN!=PASS
PRIOR_9C91_NOTE=do not transfer POST_E59D 3B72 seals
```
