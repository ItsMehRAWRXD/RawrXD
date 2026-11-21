# Clean-source build receipt — Sprint 7E (2026-11-21)

## Result: PASS

| Field | Value |
| --- | --- |
| Task | Sprint 7E — isolated clean-source configure + compile + link |
| Source commit | `5b018255d2dd739923e92c260d31d4e1f2d6ce1a` |
| Worktree | `F:\rawrxd-cleanbuild` (detached at the commit above, `git status` clean) |
| Generator | Visual Studio 17 2022, x64, Release |
| Configure | PASS |
| Compile + link | PASS |
| Build exit code | `0` |
| Executable | `F:\rawrxd-cleanbuild\build\bin\Release\RawrXD-Win32IDE-Native.exe` |
| Size | 4,371,968 bytes |
| SHA-256 | `7A3D4EADB46AE4525DC938B2D0A1A1C434DD622D96502ACD57D56831EF7912DD` |
| Build log | `cleanbuild_7E.log` (1,131,404 bytes, preserved in this directory) |

## Notes
- Built from the committed sources at `5b018255d2` in an isolated worktree, so
  the concurrent Deep2/REAP working tree was never cleaned, reset or modified.
- The active-tree builds used during Sprints 1-7 include the concurrent agent's
  uncommitted Deep2 changes; this isolated build proves the committed sources
  themselves configure, compile and link.
- The build emitted only warnings (unused parameters, C4996 u8path deprecation,
  C4335 Mac line endings in Win32IDE.h); no errors.

## Command
```
cmake --build F:\rawrxd-cleanbuild\build --config Release --target RawrXD-Win32IDE-Native -- /m
```