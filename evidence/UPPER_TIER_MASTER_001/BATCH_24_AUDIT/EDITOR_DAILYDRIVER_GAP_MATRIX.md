# EDITOR_DAILYDRIVER_GAP_MATRIX — Batch 24 prep (READ-ONLY)

```
AUDIT=UPPER_TIER_MASTER_001/BATCH_24_AUDIT/EDITOR_DAILYDRIVER_GAP_MATRIX
ASOF_UTC=2026-11-11T17:41:00Z
PRIMARY=F:\rawrxd
MASTER_PLAN=§7 Traditional editor + Batch 24 workstreams
MODE=READ_ONLY
NATIVE_REBUILD=NOT_PERFORMED
WIN32IDE_EDITS=NONE
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
NO_INVENT_PASS=1
HISTORICAL_SEAL != TIP_PROMOTE
ESTIMATES_UNCHANGED=1
```

Read-only inventory for Upper-Tier Batch 24 (editor completeness, workspace persistence, accessibility, themes, performance → daily-driver acceptance). No product/Win32IDE source edits. No `build_win32ide`. No runtime cells executed this audit.

## Controlling blockers

| id | status | note |
|----|--------|------|
| G1_NATIVE_LINK | **FAIL** | `RawrXD-Win32IDE-Native.exe` ABSENT under `build_win32ide/Release` (`BATCH_17/G1_HANDOFF.txt`) |
| G1_NATIVE_LINK (alt) | NOT_SEAL | `build_ide\bin\RawrXD-Win32IDE-Native.exe` PRESENT (1825280 B, 2026-11-10) — ≠ Batch-17 Release seal |
| BATCH17_PREREQ | OPEN | Tip daily-driver remasure blocked until Native Release link |

## Capability matrix

| capability | cluster | path (authority) | source_wired | runtime_reached | gaps (short) |
|------------|---------|------------------|-------------:|----------------:|--------------|
| core_editing_open_save_tabs_undo | editor_completeness | `Win32IDE_FileOps` / Commands / Session / tab helpers | 1 | 0 | Open/save/tabs SOURCE_WIRED; split-groups thinner; tip Release EXE ABSENT |
| find_replace_regex_workspace_search | editor_completeness | `Win32IDE_SearchPanel.cpp` | 1 | 0 | Regex find-in-files+replace source present; tip E2E NOT_RUN |
| multi_cursor_and_column_selection | editor_completeness | `Win32IDE_MultiCursor.cpp` | 1 | 0 | Multi-cursor engine SOURCE_WIRED; column/rect select not found; NOT_RUN |
| folding_brackets_indent_format | editor_completeness | `Types.h foldedRegions`; Core `initTier3Cosmetics` | **0** | 0 | `Win32IDE_Tier3Cosmetics.cpp` **ABSENT**; fold field only |
| syntax_and_semantic_highlight | editor_completeness | SyntaxHighlight / SemanticTokens / LSP | 1 | 0 | Sources present; SemanticIndex placeholder residual; tip NOT_RUN |
| navigation_chrome_minimap_outline_palette_snippets | editor_completeness | Minimap / Breadcrumbs / Outline / Palette / Shortcut / Snippet | 1 | 0 | TUs present; tip HWND acceptance NOT_RUN |
| large_file_encoding_line_endings | editor_completeness | `Win32IDE_FileOps` UTF-16 paths | 1 | 0 | Encoding care SOURCE_WIRED; large-file perf NOT measured |
| external_watch_autosave_crash_recovery | workspace_persistence | IOCPFileWatcher; autoSave; SNAP recovery | 1 | 0 | Watcher = log stubs; editor crash-recovery ≠ agent SNAP |
| workspace_session_and_layout_persistence | workspace_persistence | `saveIdeSession`/`loadIdeSession`; Session | 1 | 0 | Docs+chat JSON wired; dock/layout/theme restore thin; G021 sanitize stub |
| keyboard_focus_and_screen_reader | accessibility | SetFocus paths; G12; focus probe | 1 | 0 | No IAccessible/UIA under win32app; G12 NOT_VERIFIED |
| theme_propagation_brush_recreate_dpi | themes | Themes.cpp; `applyTheme()`; `handleThemeControlColor`; MonacoThemes | 1 | 0 | Dual theme paths; MonacoThemes empty; G01–G03/G09 NOT_VERIFIED |
| dock_layout_panels_chrome | themes | Problems / PowerShell / TerminalTabs / Chat | 1 | 0 | Sources present; G04–G06/G10 historical-only; tip NOT_RUN |
| editor_ui_performance_telemetry | performance | PerfTelemetry; IOCPFileWatcher | 1 | 0 | Counters hardcoded 0; watcher stub; no PERFORMANCE_PASS |

**Counts:** capabilities=13 · source_wired=12 · source_wired_0=1 · runtime_reached=0 · CERTIFIED=0 · PROMOTE=0

## Cluster rollup

| cluster | source_wired cells | runtime_reached | verdict this audit |
|---------|-------------------:|----------------:|--------------------|
| editor_completeness | 6/7 (fold/bracket=0) | 0/7 | SOURCE inventory only |
| workspace_persistence | 2/2 | 0/2 | Session docs+chat wired; layout incomplete |
| accessibility | 1/1 | 0/1 | Keyboard focus source; screen-reader API absent |
| themes (+ dock chrome) | 2/2 | 0/2 | Brush/CTLCOLOR wired; tip theme matrix NOT_RUN |
| performance | 1/1 | 0/1 | Invent-thin telemetry; NOT_RUN |

## Claims vs reality

| Claim / obligation | Reality (this inventory) |
|--------------------|--------------------------|
| §7 fold / bracket / indent cosmetics | Call sites without `Win32IDE_Tier3Cosmetics.cpp` on F |
| Screen-reader support | No MSAA/UIA matches under `src/win32app` |
| Theme on every native child | Named `applyTheme(string)` mainly editor; brush/CTLCOLOR broader but tip G01–G03 NOT_VERIFIED |
| Workspace + project restoration | `ide_session.json` docs+chat; panel/dock layout persistence G11 open |
| Perf telemetry / non-blocking index | Zero-filled MessageBox; IOCP watcher log stubs |
| Slim A4F daily-driver PASS | Profile=SLIM; `FULL_FEATURE_DAILY_DRIVER=FAIL`; ≠ Batch 24 tip promote |
| G01–G12 tip G | 0 PASS / 12 NOT_VERIFIED — not revalidated here |
| `build_ide\bin` Native EXE | PRESENT alt only — ≠ `build_win32ide/Release` Batch-17 seal |

## Prior sealed evidence (cited, not re-run)

- `DAILY_DRIVER_CLOSE_001` — slim A4F083DF PASS; full-feature FAIL; PROMOTE=0
- `G01_G12_MATRIX` — tip G D56FE6DD all NOT_VERIFIED
- `DAILY_DRIVER_THEME_DOCK_SEAL` — 74AA source seal; alive=false
- `editor_focus_runtime_20261102.md` — physical focus NOT_VERIFIED
- `RAWRXD_DAILY_DRIVER_DOCK_001` — historical dock smoke other SHA
- `BATCH_17/G1_HANDOFF.txt` — Native EXE absent under `build_win32ide/Release`

## Batch 24 prep blockers

1. Tip Batch-17 Release Native EXE missing — all runtime cells **NOT_RUN**.
2. Tier3 cosmetics TU missing → fold/bracket/indent **source_wired=0**.
3. No screen-reader API surface.
4. Session persist ≠ full layout/theme restore.
5. PerfTelemetry/IOCP invent-thin.
6. Do not promote slim A4F or 9FDE/74AA/F6E6 historical seals to tip CERTIFIED.
7. `build_ide\bin` alt EXE ≠ Release seal.

## Next executable gates (explicitly NOT_RUN here)

1. Batch 17 clean link of `RawrXD-Win32IDE-Native.exe` under `build_win32ide/Release`
2. Remeasure G01–G12 on that tip SHA (`PROMOTE=0`)
3. Land or HOLD `Win32IDE_Tier3Cosmetics.cpp`
4. Decide MSAA/UIA scope vs daily-driver minimum
5. Real perf counters + large-file / non-blocking index proof

Machine-readable twin: `EDITOR_DAILYDRIVER_GAP_MATRIX.json`
