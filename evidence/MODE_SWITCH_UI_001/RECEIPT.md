# MODE_SWITCH_UI_001 — receipt

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
NO_INVENT_PASS=1
ABSORB=NOT_AUTHORIZED
TIP_REBUILD=NO
RUNTIME_REACHED=1
MET_CLAIM=0
ASOF_UTC=2026-10-28T17:35:00Z
```

## Tip

| Field | Value |
|-------|-------|
| EXE | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` |
| SHA256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Port | `18971` |

## Modes

| Mode | Gate | Tip HWND | Source (post-fix, not absorbed) | Disposition |
|------|------|----------|----------------------------------|-------------|
| Ask | G01 | WM_COMMAND 1208 posted OK | IDC 5005 + radio | **RUNTIME** HWND |
| Plan | G03 | WM_COMMAND 1206 posted OK | IDC 5006 + radio | **RUNTIME** HWND |
| Agent | G02 | WM_COMMAND 1207 posted OK | IDC 5007 + radio | **RUNTIME** HWND (mode switch only; AgentRunLoop 503 ≠ this seal) |
| Debug | G04 | NOT_ON_TIP_IDC | IDC 5008 + `onAgenticModeDebug` | **SOURCE_WIRED** |

## Witness

- `logs/probe_run.txt` — `HWND_PATH_OK=1` `RUNTIME_REACHED=1` `TIP_ALIVE_AFTER_HWND=1`
- `probe_mode_switch_748b.cpp` / `build_probe.bat`

## Explicit non-claims

- No tip absorb / no tip climb / no PROMOTE
- No AgentRunLoop E2E MET (still 503 on tip)
- No Debug tip RUNTIME
- No ODS `Chat mode:` invent (appendToOutput ≠ ODS on this tip)
- Headless CLI ≠ mode HWND surface
