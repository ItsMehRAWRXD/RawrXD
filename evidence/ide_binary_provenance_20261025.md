# RawrXD IDE binary provenance — 2026-10-25

The screenshots represent different executables/configurations. Do not select by
filename alone; verify the full path and SHA-256.

## Canonical newer UI candidate

`F:\rawrxd\build_unified_clean\bin\RawrXD-Win32IDE-Native.exe`

- SHA-256: `9C9239B1F5A0387E9D33FBB62CA3A2E044111521558C7A4A0F3CD4C9B387FEEE`
- Size: 9,743,872 bytes
- CMake: `F:\rawrxd\build_unified_clean`, LTO enabled
- Embedded UI markers: `GhostText`, `Max tokens`, `4096`, `Context`, `64K`
- Source path marker: `F:\rawrxd`

This matches the screenshot with Chat model, GhostText, 4096 max tokens and
64K context indicators.

## Stale/hybrid F: build

`F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`

- SHA-256: `21DAA42E3AE5E211581BB590F503103D6E747CEBCB28FE598557454A8DF9EC30`
- Size: 1,364,992 bytes
- CMake: `F:\rawrxd\build_ide`, LTO disabled
- Embedded markers: `4096`, `512`, `Context`, `Find Results`; no `GhostText`

This is not the binary to use for the newer two-selector UI.

## Other copies

`G:\VSC0de\Deep2Engine\build_ninja\bin\rawrxd_agentic_ide.exe`

- SHA-256: `A9BBC0351B0E6FCA5420291A2B01DFD9612F11A314DFBBC30C8C3E60EDEFB846`
- Size: 286,720 bytes
- No full IDE UI markers found; treat as a helper/obsolete target.

`G:\~dev\rawrxd\build_win32_cert_x64\bin\Release\RawrXD-Win32IDE.exe`

- SHA-256: `CD3566F631C4FA320B7A29DDF0673A1A7911BD69207FDEBC4AE6EB67DB21FF61`
- Size: 331,388,928 bytes
- Embedded source marker: `G:\~dev`
- Separate checkout/build graph; do not use as the canonical F: IDE.

`C:\Users\Garrett\OneDrive\Desktop\RAWR IDE\RawrXD-Win32IDE-Native.exe`

- SHA-256: `7A7E0C425FF05B1D7D1B7B7E4D02C6B298C1D7CD0F4D66D18859356A46DDE426`
- Size: 4,770,816 bytes
- Contains GhostText, 4096, 512 and 64K markers; it is a copied artifact,
  not a reproducible build output.

## Launch rule

Use the canonical newer UI path above. Do not overwrite or delete the other
copies until any shortcuts, scripts and running processes referencing them have
been inventoried and the replacement has been physically tested.
