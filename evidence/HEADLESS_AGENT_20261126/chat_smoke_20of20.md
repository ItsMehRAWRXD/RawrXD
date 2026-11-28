# Chat smoke — 20/20 acceptance (2026-11-28)

The `--chat-smoke` is reliable: **20/20 PASS** with a proper harness.

## Harness fix
The earlier "intermittent crash" (1/10) and "file-lock" (exit 128) failures were **harness
artifacts**, not product defects:
- Fixed 800 ms sleep → replaced with **process-exit synchronization** (`Start-Process -Wait -PassThru`)
  and a **bounded file-availability check** (try to open the exe for write, retry up to 6 s)
  instead of arbitrary sleeps.
- Harness: `_bb_build/chat_smoke_harness.ps1`.

## Result
```
RUN1..RUN20 PASS
SUMMARY pass=20 crash=0 other=0 locked=0 of 20
```
Each run: cold-start → model discovery → compatible-model selection → real Ollama inference
(n4-tiny-oracle) → receipt `WATCHDOG_TOKENS=PASS` → clean exit 0.

## Product fix that closed the deterministic crash
`133721f3c8` — corrected swapped `EM_POSFROMCHAR` args (NULL output pointer) in
`Win32IDE_GhostText.cpp` + `Win32IDE_MultiCursor.cpp` (was crashing in
`Msftedit!CTxtEdit::OnPosFromChar`). The 20/20 run confirms it holds.

## State
CHAT_SMOKE=20/20 PASS  IDE_BUILD=GREEN  COMMITTED=1 PUSHED=0
The chat reliability defect is CLOSED (deterministic crash fixed; harness synchronized).