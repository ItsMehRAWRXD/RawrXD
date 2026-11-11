# REAL_EDIT_2–6 claim reconcile vs current source (HEAD dace166216)

PROMOTE=0 CERTIFIED=0 INVENT_PASS=0

| Claim area | Source status at RC time | Physical on EFC863F9… |
|---|---|---|
| Dirty EN_CHANGE → Save enable | Present in `Win32IDE_lifecycle.cpp` | GATE_02 PASS |
| Save As owner HWND lifecycle | Present in `saveFileAs()` | GATE_03 PASS |
| Save/reopen SHA integrity | Binary ofstream trunc + verify | GATE_04 PASS; ATOMIC_SAVE=NOT_EQUIVALENT |
| Session tabs persist | `saveIdeSession`/`loadIdeSession` | GATE_07 FAIL (dirty marker not restored) |
| Multi-tab buffers | `DocumentBuffer` + `switchDocumentTab` | GATE_06 NOT_VERIFIED (TCN switch independence) |
| Undo/redo | EM_UNDO/EM_REDO wrappers | GATE_08 PASS |
| External conflict | **Absent** (no mtime/conflict prompt) | GATE_09 FAIL |
| Crash recovery autosave | Session only on WM_CLOSE; hard kill loses dirty | GATE_10 FAIL |
| GhostText gen/stale reject | Present in controller | GATE_11 NOT_VERIFIED (no completion) |
| Agent revision ownership | No explicit doc revision apply token | GATE_12 NOT_VERIFIED |
| Build/Test subprocess | Wired in `Win32IDE_Commands.cpp` | GATE_13 NOT_VERIFIED (exit codes not captured) |
| Unicode round-trip | UTF-8 helpers exist; ANSI RichEdit path lossy | GATE_05 FAIL (`?` substitution on disk) |

Do not copy AAC10557 PHYSICAL_ACCEPT 01–06 PASS rows into this 15-gate matrix.
KNOWN_FAILING_SHA=3C750E19… evidence not overwritten (binary not present under F:\rawrxd).
SEAL CB34EF4E not rebuilt/absorbed.
