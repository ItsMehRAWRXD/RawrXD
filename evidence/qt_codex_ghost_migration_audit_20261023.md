# RawrXD Qt → Win32 Codex/Ghost Text Migration Audit

Date: 2026-10-23

## Result

The active IDE uses the Win32 implementation for visible Ghost Text rendering. The historical Qt conversion is preserved as reference and is not linked into the production target because it defines a separate renderer contract. Linking both would create duplicate `GhostTextRenderer` implementations and ambiguous behavior.

A real wiring gap was found and fixed: `src/win32app/Win32IDE_CodexCommands.cpp` contained the migrated Codex command handlers and `GetCodexCLI()` implementation, but was documented in `CMakeLists.txt` without being present in `WIN32IDE_SOURCES`. It is now included in the production Win32 source list.

## Historical source recovery

| Historical artifact | Evidence | Current disposition |
|---|---|---|
| `50582a6fb27be` v4.1 inline decorations | `include/agentic_text_edit.h`, `include/ghost_text_renderer.h`, `src/agentic_text_edit.cpp`, `src/ghost_text_renderer.cpp`, `src/lsp_client.*` | Preserved; API-level reference only. Current production path is Win32-native. |
| `4a5a92cf9e` local-snippet-LSP arbitration | `src/win32app/Win32IDE_GhostText.cpp`, self-test files | Integrated in current Win32 Ghost Text provider precedence and cache path. |
| `4048d9bc14` debounce/stale cancellation/TTL cache | `src/win32app/Win32IDE_GhostText.cpp` and validation docs | Integrated; current path has request sequencing, stale-drop accounting, debounce, and bounded cache. |
| `12c8737f12`, `8c6ab4c6b5` Ghost Text TTFT/regression work | Ghost Text validation history | Retained as historical evidence; no duplicate renderer added. |
| Codex command conversion | `src/win32app/Win32IDE_CodexCommands.cpp` | **Wired in this audit** via `WIN32IDE_SOURCES`. |

## Production wiring checks

- Visible overlay: `src/win32app/Win32IDE_GhostText.cpp` plus `include/ghost_text_renderer.h`.
- Win32 drawing helper: `src/win32ide/GhostTextRenderer.cpp` remains a distinct low-level renderer contract and is not mixed with the Qt-era class.
- Completion bridge: `src/ai_completion_real.cpp` is already listed in the Win32 target.
- Deep2 bridge: `src/ide/Deep2Bridge.cpp` is already listed in the Win32 target.
- Codex command handlers: now listed in the Win32 target.
- MASM ranking path: `src/asm/ghost_text_ranker.asm` is retained by the existing build configuration.
- Qt-only files remain optional/reference code; no Qt dependency was added.

## Validation

- Historical commit and source presence audit completed with `git log --all` and `git show`.
- Main CMake regeneration completed successfully after the source-list change.
- Node gateway/browser validation remains green from the Ghost integration receipt.
- Full Win32 link validation depends on the configured `RAWRXD_BUILD_WIN32IDE` option and the existing dirty build tree; no certification claim is made from source-list inspection alone.

## Remaining functional check

The next runtime check is to invoke a Codex completion command from the native IDE and verify that it reaches the existing Ghost Text request path, produces a bounded completion, and accepts/dismisses with Tab/Esc. This is separate from the already verified embedded Ghost browser connection.
