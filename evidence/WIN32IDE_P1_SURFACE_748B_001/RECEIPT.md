# WIN32IDE_P1_SURFACE_748B_001 — receipt

```
ASOF_UTC=2026-10-28T17:12:00Z
WORKSPACE=G:\~dev\rawrxd
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
AUTHORITY_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
AUTHORITY_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
748B_CLOBBER=0
```

## Per-gate SOURCE / RUNTIME

| Gate | Product path | Tip 748B bind | SOURCE | RUNTIME | Notes |
|------|--------------|---------------|--------|---------|-------|
| AGENTIC_COMPOSER_UX | `HandleAgenticComposerUX` HWND | strings: HandleAgenticComposerUX, AgenticComposerUX, No active local model | SOURCE_WIRED | NOT_RUN | Fail-closed model bind in tip; no HWND/remote invoke this seal |
| AGENTIC_COMPOSER_RUNTIME Ask/Plan/Agent | `onAgenticMode*` HWND | prior INVOKED_SURFACE on 6832 RVAs | SOURCE_WIRED | NOT_RUN | Probe RVAs not re-validated on 748B |
| SHELLLAYOUT_PHASE5 | `Win32IDE_ShellLayout` HWND chrome | PHASE=5 string in tip | SOURCE_WIRED | NOT_RUN | Geometry only; no HWND exercise |
| CONPTY_STREAM_OWNER | `Win32TerminalManager::start` → CreatePseudoConsole | CONPTY_STREAM_OWNER, GateConPty FAIL_CLOSED, CreatePseudoConsole_absent | SOURCE_WIRED | PARTIAL | Tip owner wired; API smoke RUNTIME=1 (≠ HWND PowerShell panel) |
| EMBEDDED_TERMINAL stub | `src/terminal/embedded_terminal.cpp` | old pipe-success fiction | FAIL_CLOSED_SOURCE | RELINK_PENDING | Source now refuses success without product owner; candidate freeze |
| SAFE_WRITE_ATOMIC | headless `/api/tool` write_file | SafeWriteAtomic, swa.tmp, atomic_replace_failed | SOURCE_WIRED | RUNTIME_REACHED | Port 18784; atomic+preview+rollback proved |

## SafeWrite RUNTIME proof (tip 748B)

```
METHOD=CreateProcess tip --headless --local --port 18784 + curl /api/tool
MOTD→write_file → atomic=true previewed=true rollback_id=1
safe_write_status owner=SafeWriteAtomic
safe_write_preview ok
write v2 → rollback → FS content=atomic-748B-v1 ; .swa.tmp ABSENT
LOGS=evidence/SAFE_WRITE_ATOMIC_001/logs_748B/RUNTIME_PROOF.txt
A06_MET=0 (deny conjunction + full gate still open)
```

## ConPTY disposition

```
PRODUCT_OWNER=Win32TerminalManager (tip strings present)
API_SMOKE=evidence/CONPTY_STREAM_OWNER_001/logs/conpty_owner_smoke_run.txt
API_SMOKE_RUNTIME=1
HWND_POWERSHELL_PANEL=NOT_RUN
EMBEDDED_TERMINAL=FAIL_CLOSED in source (pipe-as-ConPTY forbidden)
CANDIDATE_RELINK=TIP_FREEZE_CANDIDATE_P1_SURFACE_001 (do not clobber 748B)
```

## Explicit non-claims

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
TOKEN_SURVIVED=NOT_CLAIMED
PERFORMANCE_PASS=NOT_CLAIMED
GHOSTTEXT_ABSORB=NOT_AUTHORIZED
HWND_COMPOSER_RUNTIME=NOT_RUN
HWND_CONPTY_PANEL_RUNTIME=NOT_RUN
NOT_RUN != PASS
```
