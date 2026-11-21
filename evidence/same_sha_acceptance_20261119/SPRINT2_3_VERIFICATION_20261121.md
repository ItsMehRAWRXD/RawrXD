# Sprints 2–3 verification — 2026-11-21

Build: `RawrXD-Win32IDE-Native` (Release) — IDE_BUILD=PASS.
Probe: `gui_model_selector_probe3.ps1` (control 1206), cwd `F:\rawrxd`.

## Sprint 2 — transient blank selection eliminated
Before: sync selection was `CB_SETCURSEL(-1)` when no route resolved, i.e.
`[MODEL_SETCURSEL] stage=sync row=-1 setResult=-1 curSel=-1 count=19`
(blank combo until async discovery completed).

After (this build):
```
[MODEL_SETCURSEL] stage=sync row=0 setResult=0 curSel=0 count=19
```
Row 0 is the sentinel ("Local models / connecting to Ollama...", itemData -1).
`onModelSelectionChanged()` clears the active model for itemData < 0, so the
placeholder is visible but authorizes no inference route.

## Sprint 3 — portable model directory
Default run (no env):
```
[MODEL_DISCOVERY_PATH] path='' forced=0
[MODEL_DISCOVERY_PATH] modelsDir=F:\rawrxd\models
```
`modelsDir` is resolved by the new policy — exe-relative ancestor walk
(exe at F:\rawrxd\build\bin\Release -> .../models). No hardcoded
`F:\rawrxd\models`. Sync GGUF scan: 18 files; final combo: 234 items,
curSel=0, blank=0.

Explicit-but-invalid path (RAWRXD_MODELS_DIR=Q:\definitely\not\here):
```
[MODEL_DISCOVERY_PATH] RAWRXD_MODELS_DIR is not a directory: Q:\definitely\not\here
MODEL_ADD stage=sync count = 0
```
=> diagnostic emitted and **no silent substitution** (the exe/cwd fallbacks are
skipped when an explicit dir is configured but invalid). Truthful empty local
state; Ollama catalog still loads asynchronously.

## Final combo state (unchanged, healthy)
```
FINAL COUNT=234 CURSEL=0 BLANK_ITEMS=0
```