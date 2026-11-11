# RawrXD Current-Build Regression Receipt

Run: `RAWRXD_CURRENT_BUILD_REGRESSION_001`
Workspace: `F:\\rawrxd`
Branch: `fix/deep2-multimodel-safety-20261025`
HEAD: `2fcba4e60bcb8d5507134c2153c9245966de8602`

## Binary provenance

| Artifact | SHA-256 | Result |
|---|---|---|
| `build_ide/bin/RawrXD-Win32IDE-Native.exe` | `07C5DC9BD0F0FD2866C44EA761D04C36F39CC35CFB5F6C30674804E38023170A` | rebuilt/linked |
| `build_ide/bin-msvc/rawr.exe` | `44CAEC765B3590AD75930EBECB50CC57E03B8FF31E5928737CB580772E29589E` | rebuilt/linked |
| `build_ide/bin-msvc/rawr-reap.exe` | `725600B63F404769C731216B9E0C5A0B814FC7DB0BA77F77F795D504B813FA0F` | rebuilt/linked |
| `build_ide/bin/rawrxd_health_probe.exe` | `F86BE08113C0E6D868FB511A76CA592E7FF6E160FFB8E4E7E32920D19C088AA3` | rebuilt/linked |

Build/link completed with zero unresolved externals. `git diff --check` passed. No source files were staged or reset.

## Non-destructive runtime checks

- Health probe: exit `0`.
- `rawr-reap.exe --help`: exit `2` (expected usage result).
- No RawrXD child process remained after GUI close checks.
- Ollama API `/api/tags`: reachable; local model catalog returned.

## Current GUI observations

- Main title-bar close on the 07C5 executable: process exited cleanly; no unsaved-change prompt was present.
- Chat 2 creation: observed on the 07C5 executable. Chat 1 remained visible.
- Chat 2 deletion: **PENDING USER CONFIRMATION** immediately before the destructive click.
- Agent → Configure Model: dialog opened with visible model combo, Use Model, Cancel, and title-bar close controls. Dialog close was observed, but the accessibility click was not attributable after the native dialog cache changed; classify as runtime-pending until repeated with a fresh coordinate witness.
- Model selector: changed from `bigdaddyg-productivity-local:latest` to `qwen3:8b` in the current build; selection remained visible after refresh.
- Cloud GhostText consent: checkbox was visibly unchecked in a fresh session. No cloud route was authorized by this test.
- GhostText inline render/Tab accept/Escape dismiss: **NOT VERIFIED** on this current hash.

## Current CLI agent regression

Evidence directory: `F:\\rawrxd\\evidence\\RAWRXD_CURRENT_BUILD_REGRESSION_001\\cli_agentic`

- `qwen3:8b`: real Ollama inference, MOTD, read/edit/readback, exact one-file diff and hashes passed, but process exited `1` with `TOOL_LOOP_DETECTED`. Classification: **FAIL** (truthful nonzero exit; not promoted).
- `llama3.1:8b`: real Ollama inference and MOTD passed; model emitted `writeFile → readFile → editFiles`, `editFiles` failed with `match must occur exactly once`, and no valid readback/diff was produced. Classification: **FAIL**.
- An extra comma-separated model invocation produced `MODEL_METADATA_UNAVAILABLE`; this is an invocation artifact, not a model result.

## Promotion ledger

```ini
CURRENT_BUILD_GUI_REGRESSION=PARTIAL
MAIN_CLOSE_CURRENT_SHA=PASS_OBSERVED
CHAT2_CREATE_CURRENT_SHA=PASS_OBSERVED
CHAT2_DELETE_CURRENT_SHA=PENDING_CONFIRMATION
AGENT_DIALOG_CURRENT_SHA=PENDING_REPEATABLE_WITNESS
GHOSTTEXT_CURRENT_SHA=NOT_VERIFIED
CLI_QWEN3_CURRENT_SHA=FAIL_TOOL_LOOP_DETECTED
CLI_LLAMA31_CURRENT_SHA=FAIL_EDIT_TOOL_MATCH
PROMOTE=0
```
