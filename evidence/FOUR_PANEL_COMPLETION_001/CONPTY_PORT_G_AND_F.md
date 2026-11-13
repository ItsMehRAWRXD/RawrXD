# ConPTY capture fix — G tip_final vs F oneshot

```
PROMOTE=0
TIP_CLIMB=HOLD
ASOF_LOCAL=2026-11-09
```

## Seal (G / tip_final product path)
`g:\~dev\rawrxd\src\win32app\Win32TerminalManager.cpp`
- Sequence: `CREATE_SUSPENDED` → close PTY-side pipes → start reader → `ResumeThread`
- `STARTF_USESTDHANDLES` with null std handles
- `UpdateProcThreadAttribute(..., hPC, sizeof(hPC))` (MSDN form)
- Evidence: `TERMINAL_GATE.md` / `TERMINAL=PASS`

## F oneshot campaign path
`F:\rawrxd\src\win32app\Win32TerminalManager.cpp`
- **Already contains** the same CREATE_SUSPENDED / close-before-ResumeThread / STARTF_USESTDHANDLES sequence (verified by source grep this turn).
- **No port edit required** this turn — F already aligned with the OS 26300 capture win.
- Keep F and G tip_final consistent; do not diverge the ConPTY owner path.

## Explicit
Port task = **SATISFIED** (F already had fix). Not an invent PASS of HWND/IDE gates.
