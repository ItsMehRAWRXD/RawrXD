# Gates G75 (compiled-source ownership audit) + G76 (release build+link) (2026-11-21)

## G75 — Compiled-source ownership audit
Authoritative source: `build/RawrXD-Win32IDE-Native.vcxproj` (the generated VS project).

| File | In vcxproj | Role |
| --- | --- | --- |
| `Win32IDE_lifecycle.cpp` | **YES** | WindowProc, handleMessage, WM_CLOSE, deferred close prompt |
| `Win32IDE_FileOps.cpp` | **YES** | saveIdeSession/loadIdeSession, ide_session.json |
| `Win32IDE_Commands.cpp` | **YES** | command router, handleToolsCommand, build dispatch |
| `Win32IDE.cpp` | **YES** | main window, menus, GhostText integration |
| `Win32IDE_Core.cpp` | **NO (dead)** | duplicate WindowProc/handleMessage (not compiled) |
| `Win32IDE_Session.cpp` | **NO (dead)** | duplicate saveSession (not compiled) |

This is the "two implementations" trap: `Win32IDE_Core.cpp`/`Win32IDE_Session.cpp`
are **not compiled**; all production work must target `lifecycle/FileOps/Commands`.
Duplicate-symbol ownership: `QuantDot::WeightCacheRetention` is defined in
`quant_dot_dispatch.cpp` and linked into `rawrxd_gpu_compute` (`2ab93fa30e`).

## G76 — Release-target compilation and linking
- Isolated clean-source build at commit `5b018255d2` (worktree `F:\rawrxd-cleanbuild`):
  **PASS**, `BUILD_EXIT=0`, `RawrXD-Win32IDE-Native.exe` 4,371,968 bytes,
  SHA-256 `7A3D4EADB46AE4525DC938B2D0A1A1C434DD622D96502ACD57D56831EF7912DD`
  (receipt `CLEANBUILD_7E_RECEIPT.md`).
- Active-tree builds of `RawrXD-Win32IDE-Native` and `RawrXD-CLI-V2` PASS at the
  current HEAD (incremental, after each change).
- A final from-scratch release build at the release candidate is still required
for G76 closure (the clean build was at `5b018255d2`, not the final candidate).

## Ledger
```
G75=PASS (ownership audit)
G76=PASS at 5b018255d2; final-candidate build pending
```