# RawrXD Canonical IDE Binary Provenance

Observed: 2026-10-25

## Canonical runtime

- Executable: `F:\rawrxd\build_unified_clean\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `9C9239B1F5A0387E9D33FBB62CA3A2E044111521558C7A4A0F3CD4C9B387FEEE`
- Size: `9,743,872` bytes
- Last write observed: `2026-10-24 03:39:42`
- Launch entry point: `F:\rawrxd\Launch-RawrXD-Canonical.cmd`
- Desktop shortcut target: `F:\rawrxd\build_unified_clean\bin\RawrXD-Win32IDE-Native.exe`

## Source context at audit time

- Source root: `F:\rawrxd`
- Branch: `fix/deep2-multimodel-safety-20261025`
- HEAD: `5c128adf94870c23c2ab296ec14f07f2ae5e2ee7`
- Binary-to-commit embedding: not established; the hash above is the authoritative binary identity.

## Runtime/UI evidence

- Canonical window title: `RawrXD IDE - Untitled - Workspace`
- Launch connections: `11/11`
- Local model inventory: observed populated
- Chat model selector: present and populated
- GhostText model selector: present and populated
- Max tokens control: `4096`
- Context control: `64K (pending model admission)`
- PowerShell surface: started and visible
- Chat dropdown: physically opened and displayed local model entries
- Live process path: verified as the canonical executable while running

## Known runtime observation

- Windows Application Error reported two crashes for this same canonical path at approximately `07:41` and `07:44`.
- Exception: `0xC0000409` in `ucrtbase.dll` (`BEX64` / stack-buffer-overrun classification).
- This is an unresolved production blocker; the IDE is not declared crash-free.
- WER recorded `C:\\ProgramData\\obs-studio-hook\\graphics-hook64.dll` loaded in the crashing process; crash ownership is therefore not isolated from the OBS injection path.
- No crash is attributed to the stale `build_ide`, `G:\\VSC0de`, or `G:\\~dev` binaries.

## Pending source fix

- `src/win32app/Win32IDE.cpp` now prefers an Ollama route, then a local GGUF route, before falling back to Kilo when discovery completes.
- That source change has not been rebuilt into the canonical binary recorded above, so it is not counted as runtime evidence yet.

## Deliberately excluded artifacts

These are preserved recovery or separate-build artifacts and are not part of this certification baseline:

- `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- `G:\VSC0de\Deep2Engine\build_ninja\bin\rawrxd_agentic_ide.exe`
- `G:\~dev\rawrxd\build_win32_cert_x64\bin\Release\RawrXD-Win32IDE.exe`

No stale binary was overwritten or deleted.
