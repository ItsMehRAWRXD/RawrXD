# IDE Audit Delta + Next Steps

Baseline: `audit/RAWRXD_IDE_PARITY_AUDIT_001/AUDIT.md` ("Full IDE Audit — End-to-End Parity vs VS Code + Copilot"). Current state: this session's edits plus a concurrent editor working the same tree.

## The blocker that outranks everything else

**`RawrXD-Win32IDE` has never been compiled or linked.** `build_ide/RawrXD-Win32IDE.dir` contains zero `.obj` files and no exe exists. Every IDE change below is *source-verified only* (compiles standalone under `cl /Zs`) and has **not** been through the real target.

Root cause of the build producing nothing: `src/rawrxd_cpu_math.cpp` is compiled into at least six targets (CMakeLists.txt:362, 2265, 4497, 5549, 14122, 17327) and is under active concurrent editing. It failed mid-edit three times during this session — `C2065 'geom_': undeclared identifier`, orphaned duplicate accessor blocks, and a `generation_.load()` call on a non-atomic. The IDE target never got past that TU.

Consequence for planning: **do not treat any IDE item as done until `RawrXD-Win32IDE.exe` exists and launches.** The audit's original complaint — "a green build proves nothing about IDE completeness" — is currently worse, because there is no build at all.

## Audit delta: now CLOSED (source-verified, not built)

| Audit row | Was | Now | Evidence |
|---|---|---|---|
| Selection (keyboard) | PARTIAL | wired | `Win32IDE_EditorEngine.cpp:531` shift-extends caret moves |
| Selection (mouse drag) | MISSING | wired | `EditorEngine.cpp:538` `WM_MOUSEMOVE` + capture |
| Copy/Cut/Paste | MISSING | wired, selection-aware, UTF-8 | `Win32IDE_Commands.cpp:280-303` `CF_UNICODETEXT` |
| Undo/Redo | MISSING | wired, debounced | `Commands.cpp:690`, `EditorEngine.cpp:72` mutation hook |
| Ghost text render | MISSING (0 callers) | painted | `EditorPaint` calls `GhostText_Paint`; `EditorEngine.cpp:509,524` Tab/Esc |
| Settings GUI | MISSING (0 callers, NULL template) | wired + real template | `Commands.cpp:651`, `main_win32.cpp:2277`, `SettingsGUI.cpp:334` |
| Accelerators F5–F9, Ctrl+Shift+B | advertised, absent | present | `main_win32.cpp:2340-2345` |
| DPI awareness | MISSING | manifest + runtime call | `main_win32.cpp:2085`, `.rsrc` verified via `mt.exe` on the PE |
| Ctrl+H | destroys text | real dialog | `DoEditReplace` prompts; refuses empty search |
| `STUB_FALLBACKS=0` / `COMMAND_DISPATCH=PASS` | string literals | counted | `ChatRunTelemetry::stubFallbacks`, routed bool |
| missing-225 silent drop | `message(WARNING)` only | counted + fatal opt-in | `RAWRXD_STRICT_SOURCES`, `RAWRXD_DROPPED_SOURCE_TOTAL=225` |
| `.rc` stub / no manifest / no version | stub, never compiled | shipped | `project(... RC ...)`; `rawrxd.exe` has `.rsrc`, `FILEVERSION 14.7.3.0` |
| Single `threads` label | conflated | canonical vocabulary + per-request tally | `GeometryForRequested()`, `thread_geometry_probe` PASS |

## Still OPEN

**Blocking**
1. `RawrXD-Win32IDE` never built (above).
2. `WIN32IDE_SOURCES` still drops 225 nonexistent paths. The filter now *reports* the number, but the sources are still fictional. `RAWRXD_STRICT_SOURCES=ON` exists and is not enabled anywhere.

**Audit items confirmed still open by source read**
3. `GitPanel_GetDiff` (`Win32IDE_GitPanel.cpp:278`) and `GitPanel_GetLog` (`:284`) — defined, **zero callers**. Audit rows 209/210 stand.
4. Chat "Send on Enter" (row 115) uses `EN_UPDATE`, not a `VK_RETURN` subclass — that is change notification, not a key.
5. Terminal Enter (row 193): `Win32IDE_TerminalSplit.cpp:181-182` uses `EN_UPDATE` and its own comment defers to a subclass "via WM_CHAR"; needs verification.
6. `g_hOutput` legacy control is created over the terminal panel at a fixed `0,0,400,200`, and `ShellLayout_Resize` never resizes it.
7. `IDM_FILE_RECENT_BASE=1010` / `IDM_FILE_RECENT_CLEAR=1020` defined, never referenced; recent files are collected and never shown.
8. `Win32IDE_Commands.cpp.old` still in tree; `AutonomousAgent.cpp.bak` is a one-line stub.
9. Editor is byte-indexed ANSI end to end (`DrawTextA`, `GetTextMetricsA`, no UTF-16). Non-ASCII columns drift.
10. `Settings_Load` is never called — settings are written but never restored at startup.
11. Qt orphans still present: `src/agent/agent_hot_patcher.*`, `src/core/autonomous_model_manager.*`, `include/checkpoint_manager.h`, and the inert SoloIDE `Qt6` CMake block.
12. `src/asm/wom_sha256ni.asm` does not assemble, is referenced by nothing, and no SHA-256 KAT gates any SHA-NI claim.
13. `RawrXD-TpsSmoke` — `EXCLUDE_FROM_ALL`, sources reduced to three files with no `main`; unbuildable if requested.
14. `deep2_k2_useful_tps_001` is a one-line stub source; the exe prints nothing and exits 0. Advertised as the TPS front door.
15. Duplicate instrumentation: `thread_geometry_probe.cpp` (repo root) and `tools/thread_geometry_probe.cpp` (registered at CMakeLists.txt:17326). Pick one.

**Genuinely absent — files do not exist. Not defects; scope decisions.**
16. Minimap, breadcrumbs, multi-cursor, diff view, outline panel, problems panel, hover tooltips, inlay hints, code lens, rename preview, agent history, chat message renderer, debugger panel, extensions panel, semantic index, shortcut editor, tasks, fuzzy search. Each is a `missing-225` entry.

## Sequenced next steps

**Step 1 — Make the IDE buildable. Nothing else matters until this is green.**
- Freeze concurrent edits to `src/rawrxd_cpu_math.cpp` and `src/rawrxd_transformer.cpp`, or land them first. Two sessions editing one TU is the direct cause of the three build failures.
- `cmake --build build_ide --config Release --target RawrXD-Win32IDE`
- Verify: exe exists; then `mt.exe -inputresource` on it and confirm `assemblyIdentity` + `dpiAwareness` survive. The `GenerateManifest=false` + `/MANIFEST:NO` fix was applied to `rawrxd` and `RawrXD-Win32IDE`, but only `rawrxd` has been verified on the PE.

**Step 2 — Close the unbuilt-exe debt with runtime evidence.**
- Launch it; confirm the main window creates, File→Settings opens, Ctrl+H opens find/replace, F5 fires the toolchain gate, Tab accepts ghost text.
- Until then label all 13 "closed" IDE rows `SOURCE_VERIFIED_NOT_BUILT`.

**Step 3 — Reconcile the phantom source list.**
- Per missing entry: restore the file, or delete the line. 225 dead lines are a standing lie about what the target contains.
- Then enable `RAWRXD_STRICT_SOURCES=ON` in CI so it cannot regress.

**Step 4 — Finish the small honesty defects.**
- Render `GitPanel_GetDiff`/`GetLog` in the panel, or delete the affordances.
- Replace the two `EN_UPDATE` send paths with real `VK_RETURN` handling, or document them as notification-on-change.
- Call `Settings_Load` at startup; make the editor honour font size / line numbers / word wrap.
- Remove `g_hOutput`; add the recent-files submenu; delete `.old`/`.bak` trees.

**Step 5 — Retire the two lying harnesses.**
- `deep2_k2_useful_tps_001`: implement against `production_regime_sweep`, or delete the target. A stub advertised as the front door is worse than no target.
- `RawrXD-TpsSmoke`: give it a `main` or delete it.
- Deduplicate the thread geometry probe.

**Step 6 — Then the real scope decisions.**
- UTF-16 editor model (large; fixes every column/encoding defect at once).
- Qt orphan deletion (trivial, zero-risk, no live target references them).
- `wom_sha256ni.asm`: repair and gate on SHA-256("abc") = `ba7816bf…`, or delete it.
- The 15 genuinely-absent editor features are product decisions, not defects.

## Risks

- **Concurrent write contention is the dominant risk.** Two agents on `rawrxd_cpu_math.cpp` produced three build breaks in one session, including duplicated code blocks and orphaned members. Single-writer discipline on shared TUs is worth more than any individual fix listed here.
- The depth-16 sweep still reports `BASE_DRIFT=+25% ORDER_BIAS_SUSPECTED`. Do not read a thread optimum out of `regime_sweep` until drift is controlled.
- `git` is denied by the current session's permissions, so branch and diff state could not be inspected. Confirm nothing is half-committed before Step 1.
- Two detached `regime_sweep` runs (default threshold, and `RAWRXD_CTX_THRESHOLD=1024`) are still in flight; read their output before regenerating any speedup table.
