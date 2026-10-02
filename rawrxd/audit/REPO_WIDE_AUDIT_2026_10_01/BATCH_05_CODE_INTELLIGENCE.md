# BATCH 05 — Editor / Code-Intelligence Audit

**Repository:** `F:\~dev\rawrxd`
**HEAD:** `9f67682ffea12a182ae4fd2d41fb3bc524f61d2b`
**Tree:** dirty (193 modified/untracked paths) — audited **WORKING TREE**
**Scope:** 10 editor / code-intelligence features
**Method:** static call-chain tracing from `src/win32app/main_win32.cpp` → WM_COMMAND / accelerator / editor key handler → command router → feature registry → handlers, cross-checked against `CMakeLists.txt` target membership and `CMakeCache.txt` lane settings in every configured build directory.

---

## 0. Build-lane facts that decide *which* handler is linked

These were measured, not assumed, because two files define competing handlers for the same feature.

| Question | Measured answer | Evidence |
|---|---|---|
| Which SSOT lane is configured? | `RAWR_SSOT_PROVIDER:STRING=AUTO` in **all 31** cached build dirs (`build`, `build_ide`, `build_ide_audit`, `certbuild`, …) | default `CMakeLists.txt:3190`; cache read |
| Is `src/core/auto_feature_registry.cpp` in `RawrXD-Win32IDE`? | **YES** — appended when provider is `AUTO` | `CMakeLists.txt:5340-5341`, target `CMakeLists.txt:7290` |
| Is `src/core/ssot_handlers.cpp` in `RawrXD-Win32IDE`? | **YES** — `RAWRXD_ENABLE_MISSING_HANDLER_STUBS:BOOL=OFF` in `build_ide`, `build_ide_audit`, `certbuild`, so the `else()` lane runs and the file is *not* removed | `CMakeLists.txt:6383-6406`, `CMakeLists.txt:2723` (in base set) |
| Is `src/core/auto_feature_real_impl.cpp` in any target? | **NO** — zero references in `CMakeLists.txt` or `cmake/*.cmake` | grep, 0 hits |
| Is `src/core/win32ide_link_stubs.cpp` in the IDE target? | **NO** — only reference is the commented-out `CMakeLists.txt:6047`. Its duplicate inline `HotpatchSymbolProvider` (`win32ide_link_stubs.cpp:82-87`, `getAllSymbols(){return {};}`) therefore does **not** cause a link ambiguity | `win32ide_link_stubs.cpp:72-88` |
| Does an IDE binary exist? | **YES** — `build_ide_audit\bin\Release\RawrXD-Win32IDE.exe`, 21,724,160 bytes, 2026-10-01 18:21 | filesystem |

**Consequence:** `handleLspGotoDefinition` (auto lane) and `handleLspGotoDef` (ssot lane) are both in the shipping binary, under different names, with different behaviour. Both are analysed below.

---

## 1. Per-feature findings

| Feature | Reachable from IDE? | Handler file:line | Classification | Finding |
|---|---|---|---|---|
| **1. Go to definition** | **NO** | `src/core/auto_feature_registry.cpp:2509`; `src/core/ssot_handlers.cpp:7683` | **UNIMPLEMENTED** | No menu item (`main_win32.cpp:2879-2927` builds only File/Edit/Build/Model/Agentic/View), no `VK_F12` in the accelerator table (`main_win32.cpp:2937-2959`), no `VK_F12` case in the editor's `WM_KEYDOWN` (`Win32IDE_EditorEngine.cpp:474-531`). `Win32IDE_Commands_Route` (`Win32IDE_Commands.cpp:686-692`) handles only IDs 1000–1999 and 2100–2199 plus an empty `g_commandHandlers` map — `Win32IDE_Commands_Register` (`Win32IDE_Commands.cpp:693`) is **declared at `main_win32.cpp:53` and never called**, so the map is permanently empty. `IDM_LSP_GOTO_DEFINITION` = 5061 (`auto_feature_registry.cpp:353`) falls to `DefWindowProc`. Even if invoked, the auto-lane handler reads `HotpatchSymbolProvider::getAllSymbols()`, which is **always empty** — see TOP DEFECT #1. The ssot-lane handler has a real parser but bails in GUI mode: `if (ctx.isGui && ctx.idePtr) return routeToIde(ctx, 5061, …)` (`ssot_handlers.cpp:7686`) → dropped `WM_COMMAND` → `CommandResult::ok` (`ssot_handlers.cpp:525`). |
| **2. Find references** | **NO** | `src/core/auto_feature_registry.cpp:2486` | **CONTRACT_VIOLATED** | Textbook false success. `auto_feature_registry.cpp:2488-2501` iterates `HotpatchSymbolProvider::instance().getAllSymbols()` — a vector that is **provably empty on every call** — prints `(no matching symbols)` (`:2502`) and returns `CommandResult::ok("lsp.findReferences")` (`:2506`). The handler returns success for a scan that never scanned. `IDM_LSP_FIND_REFERENCES` = 5062 is likewise unroutable. The honest ssot implementation (`ssot_handlers.cpp:7715`, real whole-word line loop) is GUI-dead at `:7718`. |
| **3. Rename symbol** | **NO** | `src/core/auto_feature_registry.cpp:2582`; real mutator at `src/core/ssot_handlers.cpp:7753` | **CONTRACT_VIOLATED** | The auto-lane handler is **honestly repaired**: it locates the symbol, then states `"RENAME IS NOT IMPLEMENTED: no source file was modified"` and returns `CommandResult::error("Rename not implemented", -2)` (`auto_feature_registry.cpp:2621-2627`). That is correct and should be credited. It is still unreachable, and it fires `SendMessage(h, WM_COMMAND, IDM_LSP_RENAME_SYMBOL, 0)` at `:2600` — an ID with no handler. The real mutation engine is `ssot_handlers.cpp:7753-7837`: `collectSymbolMatches` → per-file `readTextFileLimited` → `replaceWholeWordOccurrences` → `writeTextFile` → reports `files_changed` / `replacements`. It requires `--apply` (`:7770`, `:7803`) and is unreachable because `if (ctx.isGui && ctx.idePtr) return routeToIde(ctx, 5063, …)` (`:7756`) returns **`ok` for a `PostMessageA` the IDE drops** (`ssot_handlers.cpp:524-525`). |
| **4. Symbol search / workspace symbol search** | **NO** | `src/core/auto_feature_registry.cpp:2811`; `src/core/ssot_handlers.cpp:4117`; `src/core/semantic_code_intelligence.cpp:635` | **UNIMPLEMENTED** | Sidebar "Search" tab exists: `Win32IDE_Sidebar.cpp:190` creates `g_hwndSearchList`, a LISTBOX titled `"Search Results"`. **Nothing ever puts an item in it** — zero `LB_ADDSTRING` / `LB_RESETCONTENT` in the file; the only operations are `ShowWindow(...SW_HIDE/SW_SHOW)` (`:99`, `:101`). No query input control is created for it. `handleLspShowSymbolInfo` reads the same always-empty provider; with no args it prints `"[LSP] Symbol info for token at cursor."` (`:2832`) — asserting a cursor read that never happens — and returns `ok` (`:2834`). `handleLspSymbolInfo` (ssot) is the one real implementation and is notable for **omitting** `return` on its `routeToIde` call (`:4120`), so it falls through and does the real search — but is still only reachable via the uncalled `rawrxd_dispatch_*` bridge. `SemanticCodeIntelligence::searchSymbols` (real, fuzzy-match loop over an indexed symbol map) is certified by `semantic_code_intelligence_cert` but has **zero** `win32app` consumers. |
| **5. Diagnostics (problems panel)** | **NO** | — | **UNIMPLEMENTED** | `src/win32app/Win32IDE_ProblemsPanel.cpp` **does not exist** although `CMakeLists.txt:5989` lists it. Three real diagnostics producers exist and all three are disconnected: (a) `Win32IDE_BuildRunner.cpp:37-72` genuinely parses MSVC/GCC diagnostic lines, but `BuildRunner_GetDiagnostics` / `BuildRunner_ErrorCount` / `BuildRunner_WarningCount` (`:186-192`) have **no consumer anywhere in `src/`**, and `BuildRunner_Run` is called only from `CICDSettings.cpp:118`, not from `IDM_BUILD_NATIVE` (which routes to `runToolchainGate()`, `main_win32.cpp:2161-2163`). (b) `Win32IDE_LSPClient.cpp:140-174` really parses `textDocument/publishDiagnostics`, but **every `LSPClient_*` entry point has zero callers** — `LSPClient_Start` (`:208`, real `CreateProcessA` + `initialize` at `:229/249`), `LSPClient_DidOpen`, `LSPClient_DidChange`, `LSPClient_RequestHover`, and `LSPClient_SetDiagnosticsCallback` (`:297`) are each defined and never called, so the language server is never launched and `LSPAI_Bridge_OnDiagnostics` (`Win32IDE_LSP_AI_Bridge.cpp:80`) is never installed. (c) `LSPHotpatchBridge::refreshDiagnostics()` (`src/lsp/lsp_hotpatch_bridge_impl.cpp:30-39`) only increments two counters and returns `ok("diagnostics refreshed")`. `Win32IDE_AgentPanel.cpp` contains no diagnostic surface. |
| **6. Code actions / quick fixes** | **NO** | `src/core/code_linter.cpp:1591` (not compiled) | **UNIMPLEMENTED** | `src/core/code_linter.{cpp,hpp}` is a genuine linter with a `QuickFix` arena (`:127-134`), per-diagnostic fix synthesis (`:541-546`), an indexed `fileQuickFixes` map (`:1366`) and a real `applyQuickFix(const char*, uint32_t, uint32_t)` that mutates and rewrites the file (`:1591-1601`). It is **excluded from every target**: the only two CMake references are commented out (`CMakeLists.txt:2925`, `:5984`). No IDE surface exists. `src/core/js_extension_host.cpp:1536-1543` registers a JS binding named `vscode.languages.registerCodeActionsProvider`, and `src/core/vscext_registry.cpp:27` lists `"CodeAction"` among capability strings — both are names, not implementations. |
| **7. Format document** | **NO** | `src/refactor/RefactorChain.cpp:1638` | **DEAD/UNBOUND** | The implementation is **real and correct**: `formatFile()` looks up the file, computes `normalizeWhitespace(f->bytes, &linesChanged, 4, &r.rulesApplied)`, sets `r.changed = (formatted != f->bytes)` (`:1649`), honours `dryRun` without writing (`:1651-1654`), and on a real change calls `writeFileAtomic` + `reindex` (`:1656-1662`). `formatAll()` aggregates (`:1665-1683`). **But `src/refactor/RefactorChain.cpp` (71,898 bytes / 1,720 lines) appears in no CMake target** — `grep refactor CMakeLists.txt` returns only `src/core/safe_refactor_engine.cpp` and an include path for `src/refactoring` (a different directory). It also has **zero consumers**: the only files referencing `RefactorChain` are `RefactorChain.h` and `RefactorChain.cpp` themselves. No IDE menu item, key, or handler exists. |
| **8. Extract function** | **NO** | `src/refactor/RefactorChain.cpp:1685` | **DEAD/UNBOUND** | Also real: `extractFunction()` validates the line range against the file (`:1697`), validates the identifier (`:1701`), rejects a name already declared anywhere in the workspace (`:1705`), locates the enclosing function body (`:1711-1719`), and computes free variables by scanning `f->tokens` for non-keyword, non-block-bound identifiers (`:1730-1744`). Same two facts as #7: the TU is in **no target** and has **no callers**. `src/win32app/Win32IDE_Refactor.cpp` and `Win32IDE_RefactoringPlugin.cpp` — the natural surfaces — **do not exist** despite `CMakeLists.txt:6128` and `:6814`. |
| **9. Find-in-files / multi-file search** | **NO** | `src/win32app/Win32IDE_SearchPanel.cpp:44` | **DEAD/UNBOUND** | `SearchWorker` (`:44-103`) is a genuine multi-file scanner: `std::filesystem::recursive_directory_iterator` (`:67`), extension allow-list (`:73`), per-line `std::getline` (`:82`), regex-or-substring `matchLine` (`:48-64`), cooperative cancel on `g_search.searching` (`:69`), 2000-result cap (`:91`). **Two independent blockers prevent any use.** (a) Visibility: the panel is created (`Win32IDE_ShellLayout.cpp:75`) but immediately hidden (`:88`), and `ShellLayout_ToggleSearch` (`Win32IDE_ShellLayout.cpp:130-138`) — the only thing that shows it — has **zero callers**, and there is no menu item or accelerator for it. (b) Root: `SearchPanel_SetRoot` (`Win32IDE_SearchPanel.cpp:292`) has **zero callers**, so `g_search.rootDir` stays empty; both entry points then refuse to run on `!g_search.rootDir.empty()` (`:230`, `:297`). Even a shown, populated panel would search nothing. |
| **10. Semantic index** | **NO** | `src/context/semantic_index.cpp`; `src/core/semantic_code_intelligence.cpp`; `src/win32app/Win32IDE_SemanticIndex.cpp` (**absent**) | **DEAD/UNBOUND** | Three separate things, none reachable. (a) `src/context/SemanticIndex.{hpp,cpp}` — an embedding/tag document store with `AddDocument`, `Search`, `SearchByText`, `SaveToFile` — has **zero callers**: the only references in the repo are its own definitions. (b) `SemanticCodeIntelligence` (`src/core/semantic_code_intelligence.cpp`) is the **best code-intelligence implementation in the repository** and was explicitly de-hollowed (see the CMake note at `:17776-17788`): `buildFileIndex` now calls `repointel::analyzeSource(text)` and propagates `a.analyzed` (`:1005-1006`), `indexFile` returns `PatchResult::error("File not readable: …")` instead of unconditional ok (`:676-686`), and `goToDefinition` / `findAllReferences` / `getCallersOf` / `getCalleesOf` / `getCallChain` / `getCompletions` / `getHoverInfo` / `searchSymbols` all query a populated map. Its consumers are `final_gauntlet.cpp`, `pdb_lsp_bridge.cpp`, `pdb_reference_provider.cpp` and the cert tool — **not one `win32app` file**. (c) `src/core/semantic_search_impl.cpp` (`SemanticCodeIndex::semantic_search`) is in **no target** and has no consumers. Finally, `CMakeLists.txt:5592` lists `src/win32app/Win32IDE_SemanticIndex.cpp` with the inline claim **`# REAL: Semantic code intelligence (file is clean, 509 lines)`** — **the file does not exist**. |

---

## 2. Why nothing is reachable: the dispatch chain has no consumer

The IDE's complete command surface, measured:

```
main_win32.cpp:2879-2927   CreateMenu -> File, Edit, Build, Model, Agentic, View  (6 menus, 26 items)
main_win32.cpp:2937-2959   ACCEL[] -> 21 entries; no F12, no Ctrl+P, no Ctrl+Shift+F
main_win32.cpp:2147-2218   WM_COMMAND -> 8 explicit cases, then default:
main_win32.cpp:2214           Win32IDE_Commands_Route(wmId)  ->  DefWindowProc
Win32IDE_Commands.cpp:686-692   Route = g_commandHandlers map (EMPTY) | 1000-1999 | 2100-2199
Win32IDE_Commands.cpp:74-99     the 1000- and 2100-range tables contain File + Edit only
```

- `g_commandHandlers` is filled only by `Win32IDE_Commands_Register` (`Win32IDE_Commands.cpp:693`). That symbol is **declared** at `main_win32.cpp:53` and **never called**. The map is empty for the life of the process.
- Every ID ≥ 2200, and every ID in 2000–2099, is unroutable. That includes `IDM_LSP_GOTO_DEFINITION` (5061), `IDM_LSP_FIND_REFERENCES` (5062), `IDM_LSP_RENAME_SYMBOL` (5063), `IDM_TOOLS_COMMAND_PALETTE` (501), `IDM_TOOLS_DEBUG` (506).
- The typed-command path does not exist either. `Win32IDE_TerminalSplit.cpp:163-167` creates a real, non-`ES_READONLY` EDIT, and `:170` launches a shell — but there is **no `WM_CHAR`/`WM_KEYDOWN` handler and no `SetWindowSubclass`**. The `WM_COMMAND` case at `:180-184` is empty, and its own comment says *"handled on VK_RETURN via WM_KEYDOWN in subclass"* — **there is no subclass**. Typed text never reaches `hProcIn`.
- The `!`-command path does not exist. `Dispatch::dispatchByCanonical / dispatchByGuiId / dispatchByCli` are reached only from the `extern "C"` bridge `rawrxd_dispatch_feature / _command / _cli` (`unified_command_dispatch.cpp:436-469`), and **those three have no callers** anywhere in `src/` or `tools/` — only their declarations (`shared_feature_dispatch.h:537-539`) and definitions. `src/core/gold_link_closure.cpp:1099-1101` even contains three no-argument `void rawrxd_dispatch_*() {}` bodies, confirming the layer is orphaned.

---

## 3. TOP DEFECTS

### D1 — `HotpatchSymbolProvider` never indexes anything, and reports success doing so
`src/lsp/lsp_hotpatch_impl.cpp:86-103`
```cpp
PatchResult HotpatchSymbolProvider::rebuildIndex() {
    idx.names.clear();  idx.details.clear();  idx.filePaths.clear();
    idx.lines.clear();  idx.layers.clear();
    // Rebuild from the IDE's live symbol surface: …  (no such query follows)
    idx.valid = true;
    return PatchResult::ok("symbol index rebuilt");
}
```
The comment at `:95-100` claims *"Seeded from the Win32IDE LSP symbol index bridge when present (queried through the weak link below)"* — **there is no weak link and no seeding code**. `getAllSymbols()` (`:67-84`) therefore returns an empty vector on every call, forever. This is the root cause that makes goto-definition, find-references and symbol-info non-functional: all three iterate it. The file header at `:14-15` claims *"fails closed when the index is not ready — no fake-success returns"*; it does the opposite.
**Impact:** every LSP symbol query in the shipping IDE answers "not found (0 symbols)" while the index layer reports success.

### D2 — Find-references returns success on a scan that never scanned
`src/core/auto_feature_registry.cpp:2486-2507` — searches the always-empty vector from D1, prints `(no matching symbols)`, returns `CommandResult::ok("lsp.findReferences")`. Exactly the hunted defect class: *"returning 'no results' when it never scanned."*

### D3 — `routeToIde` returns `ok` for a `WM_COMMAND` the IDE drops
`src/core/ssot_handlers.cpp:514-526`
```cpp
PostMessageA(hwnd, WM_COMMAND, cmdId, 0);
return CommandResult::ok(name);
```
Callers include `handleLspGotoDef` (`:7686`), `handleLspFindRefs` (`:7718`), `handleLspRename` (`:7756`), `handleLspHover` (`:7842`). None of those IDs is handled by `main_win32.cpp` or `Win32IDE_Commands_Route`, so in GUI mode each reports success while doing nothing. Note `handleLspSymbolInfo` (`:4120`) omits the `return` and therefore falls through to its real implementation — the same file uses both conventions.

### D4 — `LSPHotpatchBridge::refreshDiagnostics` fabricates `ok`
`src/lsp/lsp_hotpatch_bridge_impl.cpp:30-39` increments two counters, checks an `attached_` flag, and returns `ok("diagnostics refreshed")`. No analysis, no server, no file is touched. Its own header comment (`:13`) asserts *"The bridge never fabricates PatchResult::ok for work it did not perform."* Additionally `attached_` is initialised `false` (`lsp_hotpatch_bridge.hpp:38`) and **no `attach()` exists or is called anywhere**, so the guard at `:33` is permanently taken and `detach()` always returns `ok("already detached")` (`:50`).
Downstream: `handleLspShowDiagnostics` (`auto_feature_registry.cpp:2786-2798`) prints `"refreshed OK"` / `"refresh failed"` from this value and then **unconditionally** returns `ok`; `handleLspClearDiagnostics` (`:2480-2484`) prints `"[LSP] Diagnostics cleared and refreshed via LSPHotpatchBridge."` and returns `ok` **without inspecting the result at all**.

### D5 — `handleLspShowSymbolInfo` asserts a cursor read that never happens
`src/core/auto_feature_registry.cpp:2831-2834` — with no argument it prints `"[LSP] Symbol info for token at cursor."` and returns `ok`. There is no cursor in `CommandContext` (the repaired goto-definition handler says so explicitly at `:2518-2520`), so this is a fabricated claim.

### D6 — The entire LSP client is dead code
`Win32IDE_LSPClient.cpp` — `LSPClient_Start` (`:208`), `LSPClient_Stop` (`:256`), `LSPClient_DidOpen` (`:265`), `LSPClient_DidChange` (`:273`), `LSPClient_RequestCompletion` (`:281`), `LSPClient_RequestHover` (`:289`), `LSPClient_SetDiagnosticsCallback` (`:297`), `LSPClient_SetCompletionsCallback` (`:300`), `LSPClient_SetHoverCallback` (`:303`), `LSPClient_IsRunning` (`:306`): **each has zero callers.** No language server is ever launched, `didOpen`/`didChange` are never sent, so `publishDiagnostics` (`:140`) can never arrive. The AI-diagnostics bridge `Win32IDE_LSP_AI_Bridge.cpp` is consequently never subscribed.

### D7 — The one genuinely good code-intelligence engine is bound to nothing
`src/core/semantic_code_intelligence.cpp` — real parsing via `repointel::analyzeSource` (`:1005`), real `goToDefinition`/`findAllReferences`/`searchSymbols`/call-graph, and an honest `indexFile` that fails on an unreadable path (`:681-684`). Zero `win32app` consumers. Likewise `src/refactor/RefactorChain.cpp` (real formatter + real extract-function, both writing atomically) is in **no target** and has **no callers**. These two files are the largest single opportunity in this batch: the work exists and is correct, and nothing delivers it.

### D8 — CMake asserts implementations that do not exist
| CMake line | Claim in file | Filesystem |
|---|---|---|
| `CMakeLists.txt:5592` | `Win32IDE_SemanticIndex.cpp  # REAL: Semantic code intelligence (file is clean, 509 lines)` | **absent** |
| `CMakeLists.txt:5989` | `Win32IDE_ProblemsPanel.cpp` | **absent** |
| `CMakeLists.txt:6128` | `Win32IDE_Refactor.cpp` | **absent** |
| `CMakeLists.txt:6136`, `:6270` | `Win32IDE_Minimap.cpp` | **absent** |
| `CMakeLists.txt:6205` | `Win32IDE_PeekView.cpp` | **absent** |
| `CMakeLists.txt:5403` | `Win32IDE_Debugger.cpp` | **absent** |
| `CMakeLists.txt:6814` | `Win32IDE_RefactoringPlugin.cpp` | **absent** |
| `CMakeLists.txt:6130` | `Win32IDE_FuzzySearch.cpp` | **absent** |
| `CMakeLists.txt:6126` | `Win32IDE_Tasks.cpp` | **absent** |
| `CMakeLists.txt:6139-6141` | `Win32IDE_CodeLens.cpp`, `Win32IDE_InlayHints.cpp`, `Win32IDE_HoverTooltips.cpp` | **absent** |
| `CMakeLists.txt:6119` | `Win32IDE_CursorParity.cpp` | **absent** |

(If these targets configure, they fail; if a pre-filter removes them, the comments remain false. Either way the build file is not a reliable description of the product.)

### D9 — `Win32IDE_RuntimeCert` records a PASS that cannot fail, and a NOT_IMPLEMENTED citing an uncompiled file
`receipts/RAWRXD_IDE_RUNTIME_CERT_001_run1.txt:20` — `S14_TERMINAL_COMMAND=PASS | … read_only=0`. The gate measures only that the EDIT lacks `ES_READONLY` (`Win32IDE_RuntimeCert.cpp:376-384`). It does not check whether typed input reaches the shell, and per D2-of-§2 it does not — so the PASS is a capability-of-the-window-class, not the feature. Worse, the `NOT_IMPLEMENTED` branch's explanatory text (`Win32IDE_RuntimeCert.cpp:383`) asserts the terminal is `ES_READONLY`, which is **factually wrong** for the current source.
`receipts/…_run1.txt:15` — `S09_F12_GOTO_DEFINITION=NOT_IMPLEMENTED | GotoDefinition implemented in auto_feature_real_impl.cpp …`. The **verdict is correct**; the cited evidence is wrong: `auto_feature_real_impl.cpp` is not in any target (it also still carries the pre-repair false-success bodies at `:1148-1156` and `:1171-1179`, which is presumably why it was dropped). A receipt that names an uncompiled file as proof of an implementation is a measurement defect even when the verdict happens to be right.

### D10 — 57 registry handlers post an unroutable `WM_COMMAND`, print "opened", and return `ok`
`rg -c "SendMessage\(h, WM_COMMAND, IDM_" src/core/auto_feature_registry.cpp` = **57**. Representative: `handleToolsCommandPalette` (`:4483-4487`) posts `IDM_TOOLS_COMMAND_PALETTE` (501), prints `"[Tools] Command palette opened.\n"`, returns `ok`. `handleToolsDebug` (`:4489-4493`) prints `"[Tools] Debug session started.\n"`, returns `ok`. None of these IDs exists in the IDE menu or router. The command-palette contract is consequently reported as working at `:4485` while nothing opens — which is why `Win32IDE_RuntimeCert.cpp:284-286` records `S07_COMMAND_PALETTE=NOT_IMPLEMENTED` while the registry claims success. Two subsystems in the same binary disagree about the same fact, and the optimistic one is the one that returns `ok`.

---

## 4. What is genuinely implemented (credit where due)

Stating this precisely, because it is a small set:

- **In-buffer find / replace** — `Win32IDE_Commands.cpp:595-649` with a genuine in-memory modal dialog (`:490-577`), real `EditorEngine_Find` / `EditorEngine_ReplaceAll`, undo snapshots (`:101-121`), UTF-8 clipboard (`:292-335`), selection-aware cut/copy (`:342-366`), shift-selection caret movement (`Win32IDE_EditorEngine.cpp:471`). Reachable, working, and the previous `TODO`/`""` literals that made Ctrl+H destructive were repaired. This is the only code-intelligence feature in the product with a complete path.
- **`SemanticCodeIntelligence`** (`src/core/semantic_code_intelligence.cpp`) — real, de-hollowed, and certified by `semantic_code_intelligence_cert` (`CMakeLists.txt:17789`). Unbound to the IDE.
- **`RefactorChain::formatFile` / `extractFunction`** — real, atomic, indexed. In no target.
- **`Win32IDE_SearchPanel` `SearchWorker`** — real recursive scanner. Invisible and rootless.
- **`Win32IDE_BuildRunner::ParseDiagnosticLine`** — real MSVC/GCC diagnostic parsing. Collected, never displayed.
- **`ssot_handlers.cpp` `collectSymbolMatches`** (`ssot_handlers.cpp:1521-1576`) — a real whole-word, per-line, per-file scan. Behind a GUI branch that returns `ok` for a dropped message.
- **Two prior false-pass repairs stand and are correct:** `handleLspGotoDefinition` (`auto_feature_registry.cpp:2510-2545`, tagged `RAWRXD_P1_FALSE_PASS_GOTO_DEFINITION_001`) and `handleLspRenameSymbol` (`:2583-2627`, tagged `RAWRXD_P1_FALSE_PASS_RENAME_001`). Both now fail honestly. The gap is that neither is reachable, and the layer beneath them (D1) is still hollow.

---

## 5. Defect-class counts

```text
FEATURES_AUDITED                 = 10
VERIFIED                          =  0
IMPLEMENTED_NOT_RUNTIME_VERIFIED  =  0
BLOCKED                           =  0
CONTRACT_VIOLATED                 =  2   (find-references, rename)
UNIMPLEMENTED                     =  4   (goto-def, symbol-search, diagnostics, code-actions)
DEAD/UNBOUND                      =  4   (format, extract-function, find-in-files, semantic-index)
INVALID_MEASUREMENT               =  2   (RuntimeCert S14 PASS, RuntimeCert S09 cited evidence)
REACHABLE_FROM_IDE                =  1   (in-buffer find/replace only — not in this scope's 10)

IDE_MENU_ITEMS                    = 26    (6 menus; 0 code-intelligence items)
IDEO_ACCELERATORS                 = 21    (0 code-intelligence bindings; no F12)
WIN32IDE_COMMANDS_ROUTE_RANGES    = 1000-1999, 2100-2199 only
ROUTABLE_LSP_IDS                  =  0    (5061-5068, 501, 506 all unroutable)
HANDLER_MAP_g_commandHandlers     = EMPTY (Win32IDE_Commands_Register declared, never called)
CMake_LISTED_WIN32IDE_FILES_ABSENT = 11
REGISTRY_HANDLERS_POSTTING_DEAD_WM_COMMAND = 57
IDE_BINARY                        = build_ide_audit\bin\Release\RawrXD-Win32IDE.exe (21,724,160 B)
```

---

## BATCH 05 STATUS

```text
BATCH_05_CODE_INTELLIGENCE=COMPLETE
FEATURES_AUDITED=10
VERIFIED=0
CONTRACT_VIOLATED=2
UNIMPLEMENTED=4
DEAD/UNBOUND=4
ROOT_CAUSE=NO_DISPATCH_BRIDGE — the IDE has no reachable entry point to any code-intelligence handler;
          the 432-registration command registry is linked but its only door (rawrxd_dispatch_*) has zero callers
SECONDARY_ROOT_CAUSE=EMPTY_SYMBOL_INDEX — HotpatchSymbolProvider::rebuildIndex() clears and never populates,
          so the three handlers that depend on it answer "0 symbols" forever while reporting success
BEST_REAL_ASSETS=SemanticCodeIntelligence (parsed, certified, unbound) and RefactorChain (real format+extract, in no target)
FALSE_SUCCESS_HANDLERS_FOUND=5  (find-references, show-symbol-info, clear-diagnostics, show-diagnostics, routeToIde)
INVALID_MEASUREMENTS_FOUND=2    (RuntimeCert S14 PASS; S09 cites an uncompiled source file)
NEXT_ACTION=BIND_FIRST, THEN_BUILD — wire rawrxd_dispatch_* to the WM_COMMAND default arm at main_win32.cpp:2214,
          populate the provider index, and bind SemanticCodeIntelligence; building more engines changes nothing
          while the door is sealed
```

**Skeptical read:** this batch found no defect of the "handler returns success without searching" kind *in a reachable path*, because there is no reachable path. The false-success handlers are all behind a sealed door. That is a worse finding than a broken feature: it means every future code-intelligence handler added to this repository will also be unreachable, and every registration census that counts `registerFeature(...)` calls will keep reporting coverage that no user can invoke. **A registration count is not a reachability measurement, and this batch is the proof.**
