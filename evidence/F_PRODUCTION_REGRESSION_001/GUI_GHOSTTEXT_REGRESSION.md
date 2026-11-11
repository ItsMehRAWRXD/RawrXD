# Gate 6 — GUI/GhostText Regression

Target: `build_ide/bin/RawrXD-Win32IDE-Native.exe`

Observed on the exact current binary:

- Window created with title `RawrXD IDE - Untitled - Workspace`.
- Native UI remained responsive to accessibility inspection and input.
- Workspace tree showed `F:\rawrxd`.
- Local model selector opened and displayed the local/Ollama catalog.
- GhostText selector displayed `GhostText: Auto Local`.
- `Allow cloud GhostText for this session` was visibly unchecked.
- IDE title-bar close completed without leaving a RawrXD window.

Not verified:

- Editor open/edit/save/reload.
- Real GhostText request dispatch and suggestion delivery.
- Tab acceptance, Escape dismissal, cancellation, and stale-result prevention.

Gate 6 status: `PARTIAL_HELD`.
