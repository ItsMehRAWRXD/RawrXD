# Chat smoke 20-run campaign — hardened controller (2026-11-28)

Model: llama3.2:3b (Ollama), temp 0. Exe: RawrXD-Win32IDE-Native.exe @ 719b6ab616.

## Result: 17/18 PASS (94%), 1 intermittent process death
- 17 runs: `OVERALL=PASS`, `PROCESS_EXIT=0`, all flags=1 (model/tokens1/cancel/tokens2/editor/second), ~10–15 s each.
- 1 run (r18): `WATCHDOG_TOKENS=PASS` only — process died before finalization (the intermittent exit-1 death).

## Single full acceptance sequence: PASS
`FLAGS model=1 tokens1=1 cancel=1 tokens2=1 editor=1 second=1` → `OVERALL=PASS`, `PROCESS_EXIT=0`, 11 s.

## Remaining defect
The intermittent process death (1/18) before `finish()` — receipt has `WATCHDOG_TOKENS=PASS` but no `OVERALL`. This is the same exit-1 death (not a stage failure; all stages pass when it completes). Needs a live trace (the process dies before logging).

## State
CHAT: single-sequence PASS; 20-run 17/18 (94%); 1 intermittent death.
COMMITTED=1 PUSHED=1. NOT_APPLICABLE: 20/20 — 1 intermittent process death remains.