# TERMINAL_GATE.md — FOUR_PANEL_COMPLETION_001 Track G

```
PROMOTE=0
TIP_CLIMB=HOLD
TERMINAL=PASS
SOURCE_WIRED=1
RUNTIME_REACHED=1
HWND_POWERSHELL_PANEL=NOT_RUN
CANDIDATE_EXE_SHA256=873140373C0177611709897928FFCEA7B572E11F4D690D07FEB1312EA2E90941
HARNESS_EXE=bin/terminal_gate.exe
HARNESS_SHA256=5125CFE10FE6C89F649B401A216EA976BC44DB06D44D1EA401E41411D579094D
VERIFY_WINNER_EXE=bin/conpty_verify_winner.exe
ASOF_LOCAL=2026-11-09T09:28Z
TEST_ENV=Windows 10.0.26300 amd64 MSVC 14.44
```

## Product owner
`src/win32app/Win32TerminalManager.cpp` — CreatePseudoConsole ConPTY (not redirected-pipe-only).

## Capture fix (earned marker∈pipe)
On OS 26300 the prior path leaked `echo` to the parent console (pipe saw VT-only).
Winning sequence (matrix + verify):
1. `UpdateProcThreadAttribute(..., hPC, sizeof(hPC))` (MSDN sample form)
2. `STARTF_USESTDHANDLES` with null std handles (block parent-console attach)
3. `CREATE_SUSPENDED`
4. Close PTY-side pipe ends **before** `ResumeThread`
5. Start reader thread, then `ResumeThread`
6. `restart()` preserves callbacks across stop/start

## Commands
```
cl /EHsc /Fe:bin\conpty_verify_winner.exe harness\conpty_verify_winner.cpp
bin\conpty_verify_winner.exe
# MARKER_IN_PIPE=1 PIPE contains CONPTY_MARK_A7F3

cl /EHsc /std:c++17 /Fe:bin\terminal_gate.exe harness\terminal_gate.cpp ..\..\src\win32app\Win32TerminalManager.cpp /I..\..\src\win32app
bin\terminal_gate.exe
# logs/run_terminal_gate_v5.txt
```

## Assertions / Results
| Assertion | Result |
|-----------|--------|
| marker∈ConPTY pipe (`CONPTY_MARK_A7F3`) | **PASS** |
| compile+run C++ via ConPTY capture (`FIXED_OK`) | **PASS** |
| interrupt issued | PASS |
| ResizePseudoConsole | PASS |
| restart + capture after restart | **PASS** |
| no orphan after stop | PASS |
| PowerShell capture (`PS_MARK_B91`) | **PASS** |
| HWND PowerShell panel E2E | NOT_RUN (needs candidate IDE relink) |

## Explicit
`TERMINAL=PASS` is **harness/product-manager runtime**, not tip-freeze 748B HWND absorb.
`PROMOTE=0` `TIP_CLIMB=HOLD` `748B_CLOBBER=0`