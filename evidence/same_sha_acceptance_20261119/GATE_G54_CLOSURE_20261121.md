# G54 — CLOSURE (2026-11-21)

## Final runtime acceptance (isolated profile `evidence/g54_profile`)
```
NORMAL_RESTORE=PASS        (saved rect == restored rect)
MAXIMIZED_RESTORE=PASS     (SAVED_MAX=True, MAXIMIZED2=True)
NATURAL_SHUTDOWN=PASS      (EXITED=True, ELAPSED_MS=1409)
[G54] save ... isZoomed=1 showCmd=3 normal=(286,286,1566,1086)
```

## Root cause of the maximized failure (fixed)
`saveIdeSession()` is called ~8× per close (lifecycle.cpp:1030 deferred close,
:3413 exit, FileOps.cpp:916). A **teardown-time call with an invalid
`m_hwndMain`** skipped the `if (m_hwndMain && IsWindow(m_hwndMain))` window
block and overwrote `ide_session.json` **without** the `window` key — the last
write won.

## Fix (in the active serializer `Win32IDE_FileOps.cpp`)
- Save: `root["window"] = {x,y,width,height,maximized}` from
  `GetWindowPlacement().rcNormalPosition`, `maximized = (showCmd==SW_SHOWMAXIMIZED) || IsZoomed(m_hwndMain)`.
- Restore: `SetWindowPlacement()` (workspace coords, DPI-aware, maximized).
- **Teardown preserve**: if `root` has no `window` (window invalid at save),
  merge the previous `window` object from the existing `ide_session.json` so a
  late save cannot drop it.
- Diagnostic: `[G54] save hwndMain=%p isZoomed=%d showCmd=%d normal=(...)`.

## Model identity (separate P0)
- `models/tinyllama.gguf` = 668,788,096 B (637.8 MiB),
  SHA-256 `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0` — a real TinyLlama-1.1B-Q4_K_M.
- Non-inference stubs present: `model.gguf` (4,120 B), `test_mini.gguf` (16,992 B).
- Env: `RAWRXD_MODEL_DIR=F:\models` (a second model directory).

## Remaining G54 polish (non-blocking)
- Capture the process exit code explicitly (`$p.Refresh(); $p.ExitCode`).
- Distinctive-rectangle test (`MoveWindow(123,77,900,640)`).
- Legacy session without `window` loads (backward-compatible by design).

## Status
```
G54_NORMAL_RESTORE=PASS
G54_MAXIMIZED_RESTORE=PASS
G54_NATURAL_SHUTDOWN=PASS
G54=PASS
```