# RawrXD GhostText E2E Receipt

Date: 2026-10-30
Executable: `F:/rawrxd/build_ide/bin/RawrXD-Win32IDE-Native.exe`
SHA-256: `0DA72700674E4F9B3EB8400F3F6F9BEF1CAD1D7816701EC8ABD61C518D17B3D6`
Process: `21584`
Model route selected: `Local models / Ollama / qwen3:8b`

## Result

`WIN32IDE_GHOSTTEXT_E2E_001=PASS`

- Disposable fixture opened: `F:/rawrxd/tmp_build/ghosttext_e2e_20261030/ghosttext_fixture.cpp`
- Inline suggestion visibly rendered and was exposed by the UI accessibility tree as `a * b;`.
- Tab committed the suggestion exactly once, producing `return a * b;` in the editor buffer.
- A second suggestion was generated after a new comment trigger.
- Escape dismissed the second suggestion; its transient accessibility entry disappeared.
- The fixture was returned to the clean workspace tab and its unsaved test edits were discarded.
- On-disk fixture remained unchanged: SHA-256 `4BAB8CEFA856176FB195C60AD4A3FFF09A5F9E55D729B15F1ACBACCC7689A2E0`.
- The canonical IDE process remained alive and responsive after cleanup.
- No source diff was present under `src/`.

## Gate ledger

```ini
EXTENSIONS_DISCOVERED=25
GHOSTTEXT_CONTROLLER=READY
INPUT_SURFACES_ATTACHED=7
MODEL_ROUTE=qwen3:8b
GHOSTTEXT_GENERATION=PASS_UI_WITNESS
GHOSTTEXT_RENDER=PASS
GHOSTTEXT_TAB_ACCEPT=PASS
GHOSTTEXT_ESCAPE_DISMISS=PASS
GHOSTTEXT_CANCELLATION_CLEANUP=PASS
UNINTENDED_FILE_CHANGE=0
PROMOTE=0
```
