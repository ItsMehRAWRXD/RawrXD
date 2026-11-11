# SCREENPILOT_PUBLIC_PRODUCT_COHERENCE_001 — Receipt

## Scope
Unify product naming, claims, CTAs, and mode terminology across the public homepage (`index.html`) and the browser shell (`ide_chatbot.html`), without changing working inference/runtime behavior. Commit `31d2b8a9e` remains the frozen shell baseline.

## Changes Applied

### `index.html` (public landing page)
1. **CTA link fixed** (hero): `gui/ide_chatbot_standalone.html` → `ide_chatbot.html`
2. **CTA link fixed** (footer): `gui/ide_chatbot_standalone.html` → `ide_chatbot.html`
3. **Prompt label**: `screenpilot — desktop preview shell` → `rawrxd — screenpilot desktop preview`
4. **Agent loop modes**: `Plan / Build / Agent / Stop` → `Ask / Plan / Build / Agent`
5. **Capabilities list**: Added `Files and workspace navigation`; expanded to `Ask / Plan / Build / Agent modes`
6. **Comparison table header**: `ScreenPilot` → `RawrXD (ScreenPilot)`
7. **Why section heading**: `Why ScreenPilot?` → `Why RawrXD?`
8. **Visual block qualified**: Added explicit disclaimer — not all shell surfaces are wired to canonical Tool Authority yet; the shell is the live preview, not the final authority boundary.

### `ide_chatbot.html` (browser shell)
- No edits applied. The shell operates in `chat`/`agentic`/`ghost` modes (`setMode` at ~L12494, `toggleAgenticMode` at ~L21925). Changing mode naming inside the shell is out of scope for this coherence pass and requires a dedicated shell UX work unit.

## Deferred / Out of Scope
1. **Source Drop 2 integration (`rawrxd_screenpilot_inprocess_finish`)**: Requires the RawrXD LocalServer (`:11435`) codebase, which is not present in this workspace. The in-process adapter cannot be wired until the existing LocalServer router and Agent Coordinator are available.
2. **`rawr.exe` canonical entry point**: Does not exist in `F:\~dev` build directories. This is a known source gap. The `:11437` standalone bridge is built but cannot function without `rawr.exe`. The `:11435` in-process finish removes the `rawr.exe` subprocess hop entirely once integrated.
3. **Shell mode renaming (ASK/PLAN/BUILD/AGENT)**: Requires updating `setMode`, `toggleAgenticMode`, `executeAgenticToolLoop`, and the DOM surface in `ide_chatbot.html`. This is a separate `SCREENPILOT_SHELL_UX_00x` work unit.

## Verification
- Homepage patched and saved to disk.
- No runtime behavior was changed.
- `ide_chatbot.html` remains at baseline commit `31d2b8a9e`.

## Receipt ID
`SCREENPILOT_PUBLIC_PRODUCT_COHERENCE_001`
