# Disposition — progression candidate 323A38A0

ASOF_UTC=2026-11-09T01:22:00Z
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
CONTROLLING_SHA=55BE19B7D594118C9C803D8D7DA3B127E33C0C8C82A62BD50E4956D0AC2298A3
CONTROLLING_SEAL=UNTOUCHED
BASELINE_3B720981=IMMUTABLE

```
ACTIVE_SHA=323A38A0849EFDE08F735EF85D97009D68C4700C9670317FCC2B630E85580E37
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
T07=PASS
T08=PASS
T08_PRESERVED=10
T17=PASS
T10=FAIL_SESSION_PRESENT_NOT_RESTORED
```

## Fix applied (reviewable tip diffs)

- `Win32IDE_FileOps.cpp` — `getEditorTextUtf8ForFile` prefers EM_GETTEXTEX CP 1200 → UTF-8
- `Win32IDE_lifecycle.cpp` — `switchDocumentTab` / `addDocumentTab` / EN_CHANGE capture via EM_GETTEXTEX + EM_GETMODIFY; same-tab early return; load suppress + fail-closed rollback; `kRawrxdActivateDocTab` (WM_APP+111)
- `Win32IDE.cpp` — outgoing snapshot on tab activate uses EM_GETTEXTEX
- `Win32IDE.h` — DocumentBuffer view-state fields; `kRawrxdActivateDocTab`
- Harness SelectDocTab: pointer-free WM_APP+111 (cross-process WM_NOTIFY NMHDR* was invalid → FAIL_PRESERVED_1)

## Credit rules

- Candidate T07/T08 harness PASS on named SHA with receipts under EDITOR\
- Controlling Finish-25 count remains 19 until formal multi-gate credit (T10 residual; Cancel pending)
- No invent PASS · PROMOTE=0

RUNLOG=F:\rawrxd\evidence\PROGRESSION_FINISH25_001\EDITOR\RUNLOG_T17_T07_T08_T10.txt
