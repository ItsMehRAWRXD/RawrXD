# RECEIPT — CONPTY_STREAM_OWNER_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
SOURCE_WIRED=1
RELINK_REQUIRED=1
RUNTIME_REACHED=NOT_RUN
EXE_RELINK=0
SMOKE_RELINK=0
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T11:15:00Z
```

## Verdict

| Gate | Result |
|------|--------|
| ConPTY CreatePseudoConsole product owner | **SOURCE_WIRED** = `Win32TerminalManager` |
| PowerShell panel / terminal session bind | existing `m_dedicatedPowerShellTerminal` / `tab.manager` |
| Absent API / create fail | GateConPtyStream FAIL_CLOSED |
| HWND chrome (phase5) | unchanged; tip `6832F439…` stays |
| RUNTIME_REACHED | **NOT_RUN** |
| RELINK_REQUIRED | **1** |
| PROMOTE | 0 |

## Source edits (owned TUs only)

| File | Change |
|------|--------|
| `src/win32app/Win32TerminalManager.cpp` | CreatePseudoConsole path; GateConPtyStream; no pipe-as-ConPTY fallback |
| `src/win32app/Win32TerminalManager.h` | HPCON owner fields; ownership cite |
| `src/asm/RawrXD_ConPTY_Renderer.asm` | ownership comment → stream owner Win32TerminalManager |

ShellLayout phase5 chrome not edited.

## Explicit non-claims

```
RUNTIME_REACHED=0
CONPTY_STREAM_E2E=NOT_RUN
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
TIP_SHA_UNCHANGED=1
pty_terminal.hpp=NOT_PRODUCT_LINKED
```

## Seal paths

- `evidence/CONPTY_STREAM_OWNER_001/LAW.txt`
- `evidence/CONPTY_STREAM_OWNER_001/MATRIX.md`
- `evidence/CONPTY_STREAM_OWNER_001/RECEIPT.md`
- `evidence/CONPTY_STREAM_OWNER_001/DISPOSITION.txt`
- Closure matrix U06 / S-005 stream note → SOURCE_WIRED (RELINK_REQUIRED)
