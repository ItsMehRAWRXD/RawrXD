# RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_002 — MATRIX

`CERTIFIED=1` · `PROMOTE=0` · `TIP_CLIMB=HOLD` · `EXE_SHA=B4212E46…` · `SHA_SPLIT=PRESERVED`

Law: `NOT_RUN != PASS` · `AGENTIC_EDIT_PASS != GHOSTTEXT_PASS` · no synthetic Ollama completions · no tip absorb.

## Crash disposition (001)

| Item | Value |
| --- | --- |
| 001 EXE | `build-fd` SHA `87314037…` |
| 001 result | `0xC0000374` STATUS_HEAP_CORRUPTION before feature-probe |
| Tip freeze | `748B210A…` — PRESERVED; never overwritten |
| Prior witness | `F0988009…` (gates 1-6 only; MULTILINE NOT_RUN) |
| This seal EXE | `B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F` (witness rebuild for multiline probe) |

## Per-model GhostText (real Ollama + multiline fixture)

| # | Model | Ghost | Buf/Tab | Tab+undo | Esc | Stale | Model switch | Multiline | CERTIFIED |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `nemotron-3-nano:4b` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 1 |
| 2 | `nemotron-3.5-bolt:latest` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 1 |
| 3 | `nemotron-3.5-lightning:30b` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 1 |
| 4 | `flint:latest` | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 1 |
| 5 | `qwen3:8b` (baseline) | PASS | PASS | PASS | PASS | PASS | PASS | PASS | 1 |

All five: EXIT=0, feature-probe `passed=18 failed=0` (13 gates + 5 multiline). Receipts under `runs/<slug>/`.

## Multiline disposition

- SOURCE_WIRED via `applyProductGhost` / `handleGhostTextKey` / render split on `\n`.
- Deterministic multiline fixture (not invented Ollama completion): ghost newlines≥2; Esc no mutation; Tab mutates buffer with increased newline count.
- Witness tree `build_win32ide_link001` rebuilt only; tip freeze untouched.

## Notes

- Agentic-edit CLI PASS from sibling family does **not** transfer.
- `PROMOTE=0` · product candidate absorb = OUT OF SCOPE this seal.
- NEXT = new freeze + TOKEN64/MF regression on new SHA only after separate absorb decision.
