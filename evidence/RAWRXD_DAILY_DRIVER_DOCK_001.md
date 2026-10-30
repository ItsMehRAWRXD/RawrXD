# RAWRXD_DAILY_DRIVER_DOCK_001

Date: 2026-10-25

## Tested binary

- Source root: `F:\rawrxd`
- Branch: `fix/deep2-multimodel-safety-20261025`
- Source HEAD: `5c128adf94870c23c2ab296ec14f07f2ae5e2ee7`
- Build directory: `F:\rawrxd\build_crashfix_verify`
- Executable: `F:\rawrxd\build_crashfix_verify\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `8F2F78F3062D00EA67EC8FAE2707179665CF28041E97673B778125EEC1B0500B`
- `--health-check`: PASS (`healthy (ready=true)`, exit code `0`)

## Dock and PowerShell smoke test

- PowerShell panel starts on the canonical UI path without the prior startup
  `#< CLIXML` progress line. The known Windows PowerShell startup progress
  record is filtered at the stderr pipe boundary; real stderr remains routed
  to the UI.
- `Write-Output RAWRXD_DAILY_DRIVER_OK` was entered through the visible
  PowerShell input and executed with the visible Execute button.
- The console displayed `RAWRXD_DAILY_DRIVER_OK` and remained active.
- PowerShell owns the complete bottom dock rectangle while selected. Output,
  Errors, Debug, and Find Results child windows are hidden in that state.
- Selecting Output and Debug restored those surfaces with PowerShell hidden;
  selecting PowerShell restored the shell with the legacy surfaces hidden.
- The same Output → Debug → PowerShell switch was repeated on the final
  hash-listed executable after the launcher test.
- A window-resize gesture was exercised while PowerShell was active; the
  shell remained within its dock and the editor/chat regions remained above it.
- The live native control tree showed separate controls for the editor,
  PowerShell output/input/Execute, model selector, GhostText selector, and
  Output/Errors/Debug/Find Results tab strip.

## Launch-path correction

`Launch-RawrXD-Canonical.cmd` now targets the tested executable above. The
stale `build_ide` binary and historical `G:\` binaries are not used by the
launcher.

## Scope boundary

This receipt certifies the dock ownership, PowerShell command path, startup
stderr cleanup, launcher provenance, and health check for this binary. It does
not promote Deep2 numerical correctness, LSP, debugger evaluation, WebView2,
or autonomous edit/build/test to PASS.
