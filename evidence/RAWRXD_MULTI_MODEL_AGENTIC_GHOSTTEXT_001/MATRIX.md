# RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001 — MATRIX

`MODELS=4` · `CERTIFIED=0` · `PROMOTE=0` · `TIP_CLIMB=HOLD`

Installed local Ollama tags only (not Super/Ultra): `nemotron-3-nano:4b`, `nemotron-3.5-bolt:latest`, `nemotron-3.5-lightning:30b`, `flint:latest`.

**Law:** `NOT_RUN != PASS` · `AGENTIC_EDIT_PASS != GHOSTTEXT_PASS` · CLI edit witnesses do not transfer.

## Win32IDE / HWND

| Field | Value |
| --- | --- |
| EXE | `G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe` |
| Arg | `--test-ghost-text` |
| Result | **BLOCKED** — exit `-1073740940` / `0xC0000374` (`STATUS_HEAP_CORRUPTION`) after RuntimeSurface bootstrap; no `[feature-probe]` lines |
| Cite | `HWND_BLOCK_CITE.txt`, `ghost_probe_final_stdout.txt`, `ghost_probe_final_stderr.txt` |

## Headless (existing; not invented PASS)

| Probe | Status | Transfer to this matrix? | Cite |
| --- | --- | --- | --- |
| `ghost_pipeline_probe.cpp` | GATED synthetic fail-closed (`return -1`) | No | `G:\~dev\rawrxd\src\core\ghost_pipeline_probe.cpp` |
| `RAWRXD_AUTOCOMPLETE_E2E_001` | PASS, `OLLAMA=0` | **NOT_TRANSFER** | `G:\~dev\rawrxd\evidence\RAWRXD_AUTOCOMPLETE_E2E_001\SEAL.txt` |
| `RAWRXD_AUTOCOMPLETE_CANCEL_001` | PASS | **NOT_TRANSFER** | `G:\~dev\rawrxd\evidence\RAWRXD_AUTOCOMPLETE_CANCEL_001\SEAL.txt` |
| `RAWRXD_PRODUCT_GHOST_BIND_001` | PASS (product bind) | **NOT_TRANSFER** | `G:\~dev\rawrxd\evidence\RAWRXD_PRODUCT_GHOST_BIND_001\SEAL.txt` |

## Per-model table

| # | Model | GhostText | Real Ollama ghost | Buf until Tab | Tab+undo | Esc | Stale cancel | Model switch | Multiline | Agentic-edit (CLI ≠ GhostText) | CERTIFIED |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `nemotron-3-nano:4b` | **NOT_RUN** | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | **PASS** cite `F:\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_001\nemotron_nano_raw.txt` + `nemotron_nano_shell.json` + `em_nano_buildrun.json` | **0** |
| 2 | `nemotron-3.5-bolt:latest` | **NOT_RUN** | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | **PASS** cite `...\nemotron_bolt_raw.txt` + `nemotron_bolt_shell.json` + `em_bolt_buildrun.json` | **0** |
| 3 | `nemotron-3.5-lightning:30b` | **NOT_RUN** | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | **PASS** cite `...\nemotron_lightning_raw.txt` + `nemotron_lightning_shell.json` + `em_lightning_buildrun.json` | **0** |
| 4 | `flint:latest` | **NOT_RUN** | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | **PASS** edit cite `...\flint_raw.txt` + `flint_shell.json` (Exit=0, finished PASS, editFiles PASS); **BUILD_RUN=PENDING** (no `em_flint_buildrun.json` / no `em_flint.exe`) | **0** |

## Gate definition (all required for CERTIFIED=1 per model)

1. Real Ollama ghost/inline completion (no synthetic)
2. Buffer unchanged until Tab
3. Tab accept once + undo
4. Esc dismiss, no mutation
5. Stale cancel (type / caret / model switch)
6. Model switch changes backend
7. Multiline if supported; failure handling recorded

Until every gate is PASS for a model: `CERTIFIED=0` for that model. Matrix-wide: `CERTIFIED=0`, `PROMOTE=0`.

## Paths

- Seal root: `G:\~dev\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_GHOSTTEXT_001\`
- `SEAL.txt`, `MATRIX.md`, `HWND_BLOCK_CITE.txt`
- Per-model stubs: `models\*.txt`
- CLI agentic (separate family): `F:\rawrxd\evidence\RAWRXD_MULTI_MODEL_AGENTIC_001\`
