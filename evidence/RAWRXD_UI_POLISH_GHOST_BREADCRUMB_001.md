# RAWRXD UI Polish / GGUF Crash Boundary — 001

Date: 2026-10-25

## Canonical provenance

- Source root: `F:\rawrxd`
- Branch: `fix/deep2-multimodel-safety-20261025`
- Source HEAD at verification: `5c128adf94870c23c2ab296ec14f07f2ae5e2ee7`
- Executable: `F:\rawrxd\build_crashfix_verify\bin\RawrXD-Win32IDE-Native.exe`
- Executable size: `5,607,424` bytes
- Executable SHA-256: `5DB9CDE2CDD97CD8EC9A0E7AD5317AF1C7C43B1755884E2389C531447FAAE23D`

## Build and launch evidence

- MSVC x64 developer-environment Release rebuild: PASS
- Native health check: PASS, exit code `0`, `healthy (ready=true)`
- Canonical process launch: PASS, exact path above, process responded during verification
- Stale binaries excluded: `build_ide`, `build_unified_clean`, `G:\VSC0de`, and `G:\~dev`

## UI changes in this build

- Main model selector and independent GhostText selector retain discovered model rows.
- Model selectors remain native Win32 ComboBoxes and use the supported `SetWindowSubclass` hook only for arrow-area fallback activation. The native procedure is preserved; both controls use `CBS_NOINTEGRALHEIGHT`, `WS_TABSTOP`, a 560-pixel dropped width, and a 14-row scrollable popup.
- Chat session controls provide `New Chat`, `X`, `Restore`, and `Rollback`; closed sessions and each session's bounded chat checkpoints are retained in memory and can be restored.
- Chat rollback checkpoints capture the selected chat/GhostText routes, cloud-consent state, token/context limits, transcript, and in-flight response buffer. Rollback stops active inference, restores the prior chat state, and deliberately leaves workspace/file snapshots untouched.
- Open-file breadcrumb is maintained above the editor and contains the full path value, including all directory components.
- File Explorer enumerates every mounted logical drive through `GetLogicalDriveStringsA`, including removable, network, optical, and RAM drives; roots are loaded lazily and hidden/system entries are no longer filtered from directory listings.
- The secondary Explorer surface no longer uses a developer-specific `C:\Users\HiH8e\...` root and now chains the native TreeView procedure so selection, hit testing, and arrow expansion remain intact.
- Explorer row path allocations are released on `TVN_DELETEITEMA`, preventing repeated refreshes from leaking stale path data.
- GhostText attaches to the editor and the native text-entry surfaces wired by `initializeNativeGhostText()`.
- `Cyberpunk Neon` and `Neon Midnight` presets are available from the native theme gallery and are persisted as loadable presets:
  - `themes\cyberpunk_neon.theme`
  - `themes\neon_midnight.theme`

## GGUF crash investigation

The Windows Application Error record at `2026-10-25 08:06:49` identifies the old executable:

`F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`, exception `0xC0000409` in `ucrtbase.dll`.

The current canonical binary had no matching post-build crash record during this verification. The source was nevertheless hardened at the live GGUF boundaries:

- All UI GGUF entry points select `StreamingGGUFLoader`.
- Native CPU model admission is exception-guarded and fails closed with an IDE error instead of propagating an allocation/bind exception.
- Explorer model loading is exception-guarded and reports failure without terminating the UI.
- PowerShell module discovery no longer depends on a hard-coded developer profile; it uses `RAWRXD_POWERSHELL_ROOT`, the active workspace, the process directory, and relative fallbacks.

## Current selector runtime probe

- Canonical process: fresh exact-path smoke process, responsive after the discovery window.
- Chat model selector: control ID `1206`, `CB_GETCOUNT=252`; synthesized arrow-area click changed `CB_GETDROPPEDSTATE` from `0` to `1`.
- GhostText selector: control ID `1211`, `CB_GETCOUNT=255`; synthesized arrow-area click changed `CB_GETDROPPEDSTATE` from `0` to `1`.
- Chat rollback: control ID `1216` was disabled initially, enabled after a real `Clear` button command created a checkpoint, and disabled again after a real `Rollback` button command restored that checkpoint; the canonical process remained alive.
- Final anti-oscillation probe held both popups open at 300 ms and 1000 ms after one arrow-area click; no repeated open/close transition was observed.
- This proves item population and native popup activation in the current binary. A direct visual screenshot remains a separate physical gate.

## Remaining direct physical gates

- Mouse-visible popup list after the current rebuild: runtime open-state PASS; direct visual screenshot pending because computer-use interaction was stopped by the user’s Escape key.
- Real GGUF load of a selected model through the current canonical binary: pending; the stale crash record must not be reused as current-build evidence.
- Theme visual confirmation and selection persistence: source/build verified; direct visual click test pending.

## Current launch smoke result

- Post-link launch of the exact binary: PASS, PID `12628`, responsive during selector and rollback probing.
- Recent Windows Application Error records for the canonical path: `0` during the smoke window.

This receipt intentionally does not promote the full IDE to certified status. It records the current binary, the concrete source hardening, and the exact remaining physical gates.
