# RawrXD IDE End-to-End Implementation Audit

**Date:** 2026-08-29  
**Canonical tip at audit start:** `72e1f725b` (`origin/main`)  
**Scope:** Shipping Win32 IDE (`RawrXD-Win32IDE`) and the layers it actually boots  
**Method:** Source-traced wiring (CMake membership + `Win32IDE_Core.cpp` init + call sites). Status labels in `Win32IDE_FeatureManifest.cpp` were **not** trusted.  
**Runtime limit:** This environment is Linux. The IDE is a Win32/MSVC binary. Classifications are from code paths, not a live Windows run.

---

## How to read this

| Status | Meaning |
|--------|---------|
| **E2E** | UI/menu → real backend → real I/O or process → result visible. Usable if the OS/deps are present. |
| **IMPLEMENTED** | Substantial real logic exists and is callable, but a hop is missing (not init-wired, not default, or needs an optional DLL/server). |
| **SCAFFOLDED** | Classes, menus, panels, or protocol exist; key steps are TODO, mock, fail-soft, or unwired. |
| **STUB** | Empty body, MessageBox inventory, OutputDebugString, hardcoded fake strings, or “simulated” returns. |
| **MISSING / ORPHAN** | Not in the shipping CMake target, or the file on disk is the wrong content. |
| **THEATER** | Named as a capability that the implementation cannot deliver (CMake maintainers already said this for several “transcendence” modules). |

Conservative rule: if E2E cannot be proved from wiring, it is not called E2E.

---

## 1. What the shipping IDE actually is

**One intended GUI product:** `RawrXD-Win32IDE.exe`

| Item | Fact |
|------|------|
| CMake option | `RAWRXD_BUILD_WIN32IDE` — **defaults OFF** |
| Gate | `if(WIN32 AND RAWRXD_BUILD_WIN32IDE)` in root `CMakeLists.txt` ~L3484 |
| Entry | `src/win32app/main_win32.cpp` → `Win32IDE` |
| Editor (boot) | Win32 **RichEdit** (`RICHEDIT_CLASSW`) |
| Layout | Manual `MoveWindow` in `Win32IDE_Window.cpp::onSize` — not a dock engine |
| Terminal | `CreateProcess` + anonymous pipes → read-only RichEdit panes. **Not ConPTY** |
| Git | Shell-out to **`git.exe`** via `CreateProcess` |
| CI | `.github/workflows/rawrxd-ci.yml` passes `-DRAWRXD_BUILD_WIN32IDE=ON` |
| Production scripts | `BUILD_IDE_PRODUCTION.ps1` / `BUILD_IDE_FAST.ps1` **do not** pass that flag in configure |

### Not the shipping IDE

| Tree / target | Role |
|---------------|------|
| `RawrEngine.exe` | Headless engine; excludes `Win32IDE_*.cpp` GUI TUs |
| `RawrXD_Gold.exe` | Standalone gold/minimal main |
| `rawrxd` CLI | Opt-in (`RAWRXD_BUILD_CLI`) |
| `src/qtapp/` | Legacy Qt IDE — **not referenced** by root CMake |
| `RawrXD-ModelLoader/` | Fork with a ~15-file Win32 subset |
| `Ship/` | Agent console/GUI tools, not the monolith |
| `standalone/` | Tiny streamer/loader |
| `RawrXD-SoloIDE` | Experimental slim Win32 target |
| `history/`, `reconstructed/`, `Full Source/` | Archives / mirrors — not the live product |

---

## 2. Scale (canonical `src/` only)

| Metric | Count |
|--------|------:|
| `src/win32app/*.cpp` on disk | 470 |
| `src/win32app/Win32IDE_*.cpp` on disk | 331 |
| Unique `src/win32app/*.cpp` mentioned in root CMake | ~196 |
| Approximate orphan rate (win32app TUs not in shipping list) | **~58–61%** |
| `src/win32ide/*.cpp` | 18 (Omega1 / Integration_Wiring lane) |
| FeatureManifest catalog entries | **98**, all marked `Real` on Win32 |
| FeatureManifest self-tests with a function pointer | A handful; most are `nullptr`. Remaining tests often `return true` |

The repo also contains hundreds of thousands of non-IDE files (history runoff, extracted chats, evidence packs). `RAWRXD_INVENTORY/summary.txt` reports 314,584 files and is **not** an IDE completeness measure.

---

## 3. Honest headline

The shipping IDE is a **real Win32 shell**: files, RichEdit editing, themes, sidebar chrome, session JSON, PowerShell/git.exe, a large command table, and local GGUF/blob inference (DbgEng on MSVC, in-process MCP tools, VSIX extract + optional QuickJS). Ollama HTTP, HuggingFace download, and cloud APIs are **disabled** as inference fallbacks.

It is **not** a finished Cursor-class product. The in-tree Feature Manifest claims 98/98 Win32 features are `Real`. That catalog is a registration list, not a verification. The largest gaps are:

1. **Copilot chat send** now links the native path (`Win32IDE_private_stubs.cpp` removed from CMake). Send uses local GGUF only; if nothing is loaded, the from-scratch reverse parser lists every missing artifact.
2. **Hundreds of win32app TUs are orphaned** — written, not linked.
3. **Many panels are compiled but never `create*()`’d**; live UI is a smaller sidebar/manual-layout subset.
4. **Debugger / LSP / extensions each have 2–3 parallel stacks**; only one path per area is init-wired, and it is often the weaker one.
5. **“Transcendence” names** (mesh brain, neural bridge, hardware synthesizer, …) are **theater**. CMake comments already call them “valuation theater.”
6. **Default CMake does not build the IDE.**

---

## 4. Scorecard (shipping `RawrXD-Win32IDE`)

### 4.1 Core editing shell

| Feature | Status | Evidence |
|---------|--------|----------|
| New / Open / Save / Save As | **E2E** | `Win32IDE.cpp`, `Win32IDE_FileOps.cpp` — common file dialogs + `ifstream`/`ofstream` into RichEdit |
| Save All / Close / Recent | **IMPLEMENTED** | Same files; multi-tab model exists (`TabManager`) but primary path is `m_currentFile` + one editor HWND |
| Undo / Redo / Cut / Copy / Paste / Select All | **E2E** | RichEdit + `Win32IDE_Commands.cpp` |
| Find / Replace (current file) | **E2E** | `Win32IDE.cpp` `findText` / `replaceText` |
| Workspace search | **IMPLEMENTED** | Live path is `Win32IDE_Sidebar.cpp::performWorkspaceSearch`. `Win32IDE_SearchPanel.cpp` is compiled but `createSearchPanel()` is never called |
| Themes (16 presets → chrome + editor) | **E2E** | `Win32IDE_Themes.cpp` + `applyTheme()` on startup |
| Syntax coloring | **IMPLEMENTED** | RichEdit `EM_SETCHARFORMAT` incremental tokenizer (`Win32IDE_SyntaxHighlight.cpp`). Not LSP semantic tokens |
| Manual layout (activity bar, sidebar, editor, bottom, status) | **E2E** | `Win32IDE_Window.cpp::onSize` |
| Advanced docking | **SCAFFOLDED / ORPHAN** | `ui/advanced_docking_system.cpp` not in CMake; `win32ide_docking_integration.cpp` is a demo |
| MonacoCore (D2D) / WebView2 Monaco | **IMPLEMENTED** | Real engines + factory. `initEditorEngines()` is **not** in Core startup; RichEdit is the boot editor |
| Scintilla | **ORPHAN** | Loader exists under `src/ui/`; not boot path |
| Session persist (`%APPDATA%\RawrXD\session.json`) | **IMPLEMENTED** | Real JSON R/W in `Win32IDE_Session.cpp`; Core save/restore on create/destroy |
| Settings GUI + sovereign JSON | **IMPLEMENTED** | `Win32IDE_Settings.cpp` + `Win32IDE_SettingsGUI.cpp`; parallel INI lane in `src/win32ide/SettingsPersistence.cpp` |
| Problems panel | **IMPLEMENTED** | `initProblemsPanel()` from Core; aggregator exists. Full E2E needs LSP/compiler feed |
| Minimap / cosmetics | **IMPLEMENTED** | `initTier1Cosmetics()` / `initTier3Polish()` from Core |
| File watcher (IOCP) | **SCAFFOLDED** | Handler is MessageBox/demo-grade, not explorer sync |

### 4.2 Terminal, Git, PowerShell

| Feature | Status | Evidence |
|---------|--------|----------|
| Terminal panes | **IMPLEMENTED** | `Win32TerminalManager.cpp` — `pwsh`/`powershell`/`cmd` via pipes. Not ConPTY. Often needs explicit start |
| Split terminal / tabs | **SCAFFOLDED** | Extra TUs exist; primary UX is pane + RichEdit log |
| Git status / stage / commit / push / pull | **IMPLEMENTED** | Sidebar SCM + `executeGitCommand()` → `git.exe`. `Win32IDE_GitPanel.cpp` unwired |
| PowerShell execute | **IMPLEMENTED** | `Win32IDE_PowerShell.cpp` CreateProcess + capture |
| PowerShell panel | **IMPLEMENTED** | `Win32IDE_PowerShellPanel.cpp` |
| Advanced PS remoting / providers | **SCAFFOLDED** | Large header surface; not all implemented |

### 4.3 Chat, agent, inference

| Feature | Status | Evidence |
|---------|--------|----------|
| Copilot chat UI HWNDs | **IMPLEMENTED** | Created in `Win32IDE_VSCodeUI.cpp` |
| Copilot **send → model** | **IMPLEMENTED** | `HandleCopilotSend_Ollama()` uses local native engine only. No Ollama HTTP fallback. Missing model/agent/extension/file lists come from `src/streamer/LocalStreamReverseParser` |
| `HandleChatPanel` / message renderer command handlers | **STUB** | MessageBox feature lists only (`Win32IDE_ChatPanel.cpp`, `Win32IDE_ChatMessageRenderer.cpp`) |
| Backend switcher | **IMPLEMENTED** (local only) | Remote backends (Ollama/OpenAI/Claude/Gemini/Copilot/Amazon Q) probe as disabled. `routeToLocalGGUF` is the live path |
| LLM router | **IMPLEMENTED** (local only) | All tasks prefer `LocalGGUF`; cloud/Ollama fallbacks off |
| Local stream reverse parser | **IMPLEMENTED** | From-scratch GGUF + embedded-blob stream parser (`src/streamer/LocalStreamReverseParser.*`). Header/metadata/tensor names only. `parseLocalArtifact` always fills `present[]` / `missing[]`. Linux test: `RawrXD-LocalStreamReverseParserTest` |
| Bounded agent loop + tool dispatch | **IMPLEMENTED** | `BoundedAgentLoop`, `Win32IDE_AgentPanel.cpp`, `AgentToolHandlers` (real file/shell I/O). Prefers `RawrXD_InferenceEngine.dll`; falls back to backend switcher |
| Agentic bridge | **IMPLEMENTED** | CPU engine → orchestrator → `routeInferenceRequest` |
| Autonomy loop | **IMPLEMENTED** | `Win32IDE_Autonomy.cpp` — rate-limited tick + bridge tools |
| Ask / Agent / Plan mode handlers | **SCAFFOLDED** | Prompt-mode headers; Plan has more wiring |
| Ghost text | **IMPLEMENTED** | `initGhostText()` on startup; Deep2 / native / snippet. Ollama HTTP provider is not constructed |
| Chat token streaming UX | **IMPLEMENTED** | Stream append on the local native send path |
| Model-load streaming UX | **IMPLEMENTED** | Progress UI in `Win32IDE_StreamingUX.cpp` |
| Multi-response engine | **STUB** | Hardcoded template strings; no LLM call |
| Sub-agent core (chain/swarm) | **IMPLEMENTED** | `subagent_core.cpp` via `m_engine->chat()` |
| Swarm panel / HexMag fan-out | **STUB / SCAFFOLDED** | Heartbeat/register; no inference fan-out |
| MCP in-process tools | **E2E** (in-process) | `initMCP()` + `registerBuiltinTools` (read/write/search/run_command) |
| MCP HTTP/SSE / stdio host | **STUB** | Comment: transport is future work |
| MCP binary hooks | **STUB** | Fixed-RVA jump hooks aimed at another binary |
| Vision encoder | **SCAFFOLDED** | UI + GGUF zone load; `describeImage` is embedding-stat heuristics, not a VLM |
| Semantic index (core) | **IMPLEMENTED** | Symbol indexer library |
| Semantic index (IDE UI) | **STUB / SKIPPED** | `showSemanticIndex()` stub; `Win32IDE_SemanticIndex.cpp` skipped in CMake |
| Slash commands | **SCAFFOLDED** | Registry/help; `/ping` `/echo` router |
| `Win32IDE_AIFeatures.cpp` / `_Real.cpp` | **ORPHAN** | Identical Ollama clients; **not in CMake** |
| `gguf_loader_masm*.cpp` | **ORPHAN** | Duplicate parse loaders; production uses `src/gguf_loader.cpp` |
| Headless lane-B “production” | **STUB / ORPHAN** | Fake ready strings; not the linked subagent path |
| Local inference HTTP server (port 11435) | **IMPLEMENTED** | `Win32IDE_LocalServer.cpp` (~5k lines, WinSock2, Ollama/OpenAI-shaped routes). `startLocalServer()` from Core. Needs a loaded model for generation E2E |
| Agent command allowlist (`terminal_execute`) | **IMPLEMENTED** | Prefix list: `git cmake ninja make ctest echo cat ls dir pwd cl` — **`cmd` is not listed** (`agentic_controller_wiring.cpp` ~L348) |
| Agent tools `execute_command` | **IMPLEMENTED** | Always wraps with `cmd.exe /C` (`AgentToolHandlers.cpp` ~L558). Separate `allowedCommands` vector; empty by default |

### 4.4 Debugger, LSP, extensions, compiler, RE

| Feature | Status | Evidence |
|---------|--------|----------|
| Native DbgEng debugger (MSVC) | **IMPLEMENTED** | `NativeDebuggerEngine` + `Win32IDE_Debugger.cpp` / `initPhase12()`. `createDebuggerUI()` not called from Core |
| Sidebar F5 / step / continue | **STUB** | `Win32IDE_Sidebar.cpp` sets flags / logs only — conflicts with Debugger.cpp |
| DAP client (`cdb.exe --interpreter=vscode`) | **IMPLEMENTED** but **unwired** | `DapService` / `Win32IDE_DebuggerIntegration` not in Core init |
| DAP server (port 5678) | **SCAFFOLDED** | Protocol surface; launch calls Sidebar stub |
| `DebugIntegration` (Omega1) | **SCAFFOLDED** | `DEBUG_PROCESS` loop; breakpoint inject / stack / locals TODO |
| Autonomous debugger | **STUB** | MessageBox + JSON stats |
| Non-MSVC debugger | **STUB** | “Launch simulated” |
| In-process LSP server | **IMPLEMENTED** | `initLSPServer()` at startup — regex symbol index, not clangd |
| External LSP client (clangd / pyright / tsserver) | **IMPLEMENTED** | `CreateProcessA` + JSON-RPC; **on demand**, not Core boot |
| AdvancedLSP / NotebookLSP | **STUB** | Hardcoded mock symbols / tokens |
| VSIX install + marketplace panel | **IMPLEMENTED** | `VSIXInstaller` + `initMarketplace()`; extract to `%APPDATA%\RawrXD\extensions` |
| QuickJS `extension.js` host | **IMPLEMENTED** (conditional) | `initVSCodeExtensionAPI()`; real only if QuickJS is compiled in |
| ExtensionHost / ExtensionManager (MASM isolate) | **SCAFFOLDED** | Manifest scan; fail-soft `processId = 0`; no JS |
| Native DLL plugins | **IMPLEMENTED** | `LoadLibraryW` + `RawrXD_PluginInitialize`; `initPluginSystem()` from Core |
| Compiler panel / CompilerIntegration | **IMPLEMENTED** | Real compiler invoke + output capture — **not** the Integration_Wiring menu path |
| Integration_Wiring compile/run | **SCAFFOLDED** | TODOs: console, status bar, error parse; `RunWithOutput` unused |
| PE / disasm / SSA / decompiler view | **IMPLEMENTED** | RE menu → lift → D2D split view. Heuristic/pattern quality, not Ghidra-class |
| Hotpatch panel + unified manager | **IMPLEMENTED** | `initHotpatchUI()`. `Win32IDE_HotpatchWiring.cpp` on disk is a **HeadlessIDE duplicate** (wrong file) |
| LSP ↔ hotpatch bridge | **SCAFFOLDED** | Handlers exist; `attach()` never called |

### 4.5 Voice, collab, telemetry, security

| Feature | Status | Evidence |
|---------|--------|----------|
| Voice capture / playback | **IMPLEMENTED** | `waveIn`/`waveOut` in `src/core/voice_chat.cpp`; UI panel + PTT from Core |
| Speech-to-text | **IMPLEMENTED** (HTTP) | WinHTTP to configured `/transcribe`. No local Whisper in this path |
| Voice automation / SAPI TTS | **IMPLEMENTED** | `ISpVoice` in `voice_automation.cpp`; panel created from Core |
| Collab / CRDT | **SCAFFOLDED** | `Win32IDE_Collab.cpp` in CMake; not treated as E2E without a live peer path |
| Telemetry / flight recorder | **IMPLEMENTED** | `initTelemetry()` / `initFlightRecorder()` |
| Plugin / update signatures | **SCAFFOLDED** | Command-routable handlers; not a full update channel E2E |
| AutoHealer | **SCAFFOLDED** | Diagnostic thread + MessageBox copy |
| OS Explorer interceptor | **SCAFFOLDED** | MinGW lane reports unavailable |
| Vulkan renderer | **IMPLEMENTED** (optional) | Dynamic `vulkan-1.dll` load; GPU flag in Core |

### 4.6 Transcendence / named speculative systems

CMake (~L4843–4862) removed the Win32 handler TUs and labeled them fiction. Core engines may still link.

| Name | Honest status |
|------|----------------|
| Mesh Brain | **THEATER** — in-process topology/CRDT fallbacks; not distributed consciousness |
| Speciator | **THEATER** — evolution-themed wrapper |
| Neural Bridge | **THEATER** — stats bump; no neural interface hardware |
| Omega Orchestrator | **THEATER** — scheduler singleton |
| Hardware Synthesizer | **THEATER** — Verilog/JTAG-shaped API; no fab |
| Self-Host Engine | **THEATER** — recursive self-compile claims exceed compiler integration |
| Transcendence Coordinator | **THEATER** — sequences the above |
| Transcendence **panel** | **SCAFFOLDED** — still linked (`Win32IDE_TranscendencePanel.cpp`) |
| Cursor Parity | **IMPLEMENTED** (integration glue) — “parity” is aspirational |

---

## 5. Boot wiring (what Core actually starts)

From `src/win32app/Win32IDE_Core.cpp` (representative init sequence after window create):

| Called | Area |
|--------|------|
| `initSyntaxColorizer` | RichEdit coloring |
| `initGhostText` | Inline completions |
| `initBackendManager` / `initLLMRouter` | Inference routing |
| `initializeAgenticBridge` | Agent tools |
| `initFailureDetector` / `initAgentPanel` / `initAgentHistory` / `initFailureIntelligence` | Agent UX |
| `initPhase10` | Execution governor |
| `initMultiResponse` | Multi-response (stub internals) |
| `initLSPServer` | **In-process** LSP only |
| `initHotpatchUI` | Hotpatch |
| `initPhase11` | Swarm compile scaffolding |
| `initPhase12` | Native debugger engine (MSVC) |
| `initDecompilerView` | D2D decompiler |
| `initVoiceChat` + voice panel/hotkeys | Voice |
| Voice automation panel | TTS |
| `initTier3Polish` / `initTier1Cosmetics` / `initQuickWinSystems` | QoL |
| `initChainOfThought` | Multi-model review |
| `initTelemetry` / `initFlightRecorder` | Telemetry |
| `initMCP` | In-process MCP tools |
| `initVSCodeExtensionAPI` | QuickJS/VSIX host |
| `initPluginSystem` | Native DLL plugins |
| `startLocalServer` | HTTP :11435 |
| `initAllFeatureModules` + routing verification | Feature modules (startup can `WM_CLOSE` on fail) |
| `initMarketplace` | Marketplace panel |
| `initProblemsPanel` | Problems |

**Not started at boot (but code exists):** `initEditorEngines` (Monaco/WebView2), `initLSPClient` / `startAllLSPServers` (clangd), `createDebuggerUI`, `createGitPanel`, `createSearchPanel`, DAP client attach, ConPTY terminal.

---

## 6. Critical defects (highest leverage)

### 6.1 Chat send is stubbed in the same target as the real implementation

```8:14:src/win32app/Win32IDE_private_stubs.cpp
void Win32IDE::HandleCopilotSend_Ollama() {
    OutputDebugStringA("[Win32IDE] HandleCopilotSend_Ollama stub called\n");
}
```

The same two methods are fully implemented in `Win32IDE_ChatPanel_Ollama.cpp` (~L337, ~L429). CMake links **both**. That is either **LNK2005** (duplicate symbol) or a stub that silently wins. Either way, **Copilot panel send is not a verified E2E path.**

### 6.2 FeatureManifest is not a source of truth

`src/win32app/Win32IDE_FeatureManifest.cpp` marks every Win32 row `FeatureStatus::Real`, including vision VLM, swarm, chat panel, and transcendence. Self-tests are almost all missing or compile-time tautologies (`testSyntaxEngine` returns `true`).

`FeatureRegistry.cpp` is more cautious (`Omega Orchestrator: not implemented`, `Extension Host: stub`) but **is not linked** into Win32IDE.

### 6.3 Two agent allowlists; `cmd` is missing from one

| Path | Policy |
|------|--------|
| `AgentToolHandlers::ExecuteCommand` | Always `cmd.exe /C <command>` |
| `AgentToolHandlers::RunShell` | Optional `allowedCommands` (empty = allow all) |
| `agentic_controller_wiring.cpp` `terminal_execute` | Prefix allowlist **without** `cmd` |

A repaired exe that agents launch via `cmd /c …` will be rejected on the wiring path until `cmd` is added to that prefix list.

### 6.4 Dual APIs that contradict each other

| Surface A | Surface B | Result |
|-----------|-----------|--------|
| `Win32IDE_Debugger.cpp` (DbgEng) | `Win32IDE_Sidebar.cpp` debug stubs | F5/step may no-op |
| `Win32IDE_ChatPanel_Ollama.cpp` | `Win32IDE_private_stubs.cpp` | Send path undefined/stubbed |
| Compiler panel (captures stdout) | `Integration_Wiring::CompileFile` (no capture) | Menu compile looks “dead” |
| In-process LSP | External clangd client | Boot has regex LSP only |
| QuickJS VSIX | MASM ExtensionHost | Only QuickJS is Core-init |

### 6.5 Wrong file on disk

`Win32IDE_HotpatchWiring.cpp` is a HeadlessIDE copy, not hotpatch wiring.

---

## 7. Duplicate / abandoned IDE trees

Do not add these together when scoring “is the IDE done.”

```
/workspace/src/win32app          ← shipping monolith (partially linked)
/workspace/src/win32ide          ← Omega1 / Integration_Wiring
/workspace/src/qtapp             ← abandoned Qt
/workspace/RawrXD-ModelLoader    ← slim fork
/workspace/Ship                  ← agent tools
/workspace/standalone            ← streamer
/workspace/history, reconstructed, Full Source  ← archives
```

`Win32IDE_Core.cpp` vs `Win32IDE_Core_HEAD.cpp` is a duplicate Core; CMake uses `Win32IDE_Core.cpp`.

---

## 8. Linker-stub / production-named files

These exist to close MASM/C++ symbols, not to implement IDE features:

- `src/core/unlinked_symbols_batch_*.cpp` (many kept)
- `src/core/rdna3_stubs.cpp`, `vulkan_kernel_stubs.cpp`, `spengine_stubs.cpp`
- `src/win32app/Win32IDE_private_stubs.cpp` (**harmful** — shadows chat)
- `*_production.cpp` files are mixed: some real, some empty wrappers

CMake can `EnforceNoStubs` when `RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF`. That gate does not mean the GUI chat path is real.

---

## 9. What is genuinely E2E today (conservative list)

Assume a Windows MSVC build with `-DRAWRXD_BUILD_WIN32IDE=ON`, `git.exe` on PATH, and optional Ollama/GGUF:

1. Create/open/save a text file in RichEdit  
2. Edit, undo, find/replace, apply a built-in theme  
3. Show/hide sidebar and bottom panel (manual layout)  
4. Run git status/stage/commit from the **sidebar** (not GitPanel.cpp)  
5. Start PowerShell and run a command  
6. Persist session JSON across restart (layout/theme/files — tab restore less certain)  
7. Route a prompt through backend-switcher **commands** (not Copilot Send) if Ollama or a loaded GGUF is available  
8. Ghost-text request if a provider answers  
9. In-process MCP file/shell tools  
10. Install a VSIX to disk; **run JS only if QuickJS is linked**  
11. Open RE → decompiler view on a PE (heuristic output)  
12. Hotpatch **UI** against a loaded GGUF (engine-dependent)  
13. Local HTTP server listen on 11435 (generation needs a model)  
14. Voice capture via waveIn (transcription needs an HTTP STT endpoint)

---

## 10. What is not E2E (high-visibility)

| User-facing promise | Reality |
|---------------------|---------|
| Copilot chat Send | Stub / duplicate-symbol hazard |
| “Chat Panel” / “Chat Renderer” menu handlers | MessageBox inventories |
| Cursor-class inline Monaco on boot | RichEdit; Monaco is opt-in and not Core-init |
| ConPTY integrated terminal | Pipe + log pane |
| F5 debugging | Sidebar stub vs DbgEng vs unwired DAP |
| clangd diagnostics at startup | In-process regex LSP only |
| VS Code extensions running | Extract yes; JS only with QuickJS; other hosts fail-soft |
| Multi-file Composer as Cursor | Agent panel + staged edits **IMPLEMENTED**; chat send broken |
| Multi-response compare | Fake strings |
| Semantic index panel | Stub / skipped TU |
| Vision “describe image” | Heuristic, not a VLM |
| Swarm / mesh / neural / FPGA / self-host | Theater |
| FeatureManifest 100% Real | False |

---

## 11. Scaffolded vs stub vs missing (roll-up)

Approximate counts for **shipping-target features** (not the 98-row manifesto, not the 470-file folder):

| Bucket | Approx. | Examples |
|--------|--------:|----------|
| E2E | ~15–20 | File/edit/theme/sidebar layout; sidebar git; PS exec; in-process MCP |
| Implemented (real, not fully closed) | ~35–45 | Terminal, session, settings, ghost text, agent loop, backend switcher, DbgEng, VSIX, compiler panel, RE view, local server, voice I/O |
| Scaffolded | ~25–35 | Docking, DAP server, Omega1 debug, ExtensionHost, Integration_Wiring build, collab, slash, Ask/Plan modes, IOCP watcher |
| Stub | ~15–20 | Copilot send (effective), chat MessageBox handlers, multi-response, AdvancedLSP, Sidebar debug, autonomous debugger, MCP transport |
| Orphan / missing from target | **~270 win32app TUs** | SemanticIndex, AIFeatures, ExtensionHost family, MeshBrain handlers, many experiments |
| Theater | ~8 named systems | Transcendence stack |

These are judgment bins for planning, not a second fake “completeness %.”

---

## 12. Build notes for anyone verifying on Windows

```text
cmake -S . -B build -DRAWRXD_BUILD_WIN32IDE=ON
cmake --build build --target RawrXD-Win32IDE
```

Do **not** assume `BUILD_IDE_PRODUCTION.ps1` configured that option.

Suggested smoke (after a successful MSVC link):

1. File → Open → type → Save (RichEdit path).  
2. Copilot Send — expect stub silence or a link error until `Win32IDE_private_stubs.cpp` is removed/guarded.  
3. Agent panel loop with Ollama **or** `RawrXD_InferenceEngine.dll`.  
4. `IDM_DEBUG_ATTACH` vs F5 — confirm which stack runs.  
5. Install a `.vsix` — confirm QuickJS logs vs fail-soft.  
6. Compile via Compiler panel vs Integration_Wiring menu — compare stdout.

---

## 13. Explicitly out of scope / still deferred

Per prior lineage (not re-opened here):

- Independent `_overflow/` evaluation  
- Default-branch switch `master` → `main`  
- **AGENT-E2E-002**  
- STREAM-001..010 cert rebuild on this Linux agent (no `STREAM-00x` IDs in canonical `src/`; streamer work lives under `standalone/model_streamer`, GGUF streaming loaders, and evidence packs)  
- Import from `365daa6f3` / `_overflow/` — **not done**, and not required for this audit  

Dependency deltas already on `main` (Maven/npm/Keras) were not re-imported.

---

## 13b. Follow-up implemented on this branch (2026-08-29)

Policy: **native local inference only**. No Ollama daemon, HuggingFace download, or cloud API as fallback.

| Piece | What landed |
|-------|-------------|
| From-scratch reverse parser | `src/streamer/LocalStreamReverseParser.hpp/.cpp` — streams local files, scans for GGUF magic (including embedded blobs), parses header + all 13 GGUF v3 KV types + tensor names (no weights). Always fills `present[]` / `missing[]` for model / agent / extension / file. |
| Diagnostics | `Win32IDE_StreamLoadDiagnostics.cpp` calls the reverse parser (does **not** wrap `StreamingGGUFLoader`). Failed loads print the full missing list. |
| Linux test | `RawrXD-LocalStreamReverseParserTest` — pure GGUF, 256-byte-prefixed blob, truncated header, missing path, extension sidecars. |
| Chat / router / switcher | Local GGUF only. Remote probe/route paths return a native-only error. |
| Resolver | Rejects HuggingFace and HTTP URLs. On-disk blobs may still resolve to a local path. |

---

## 14. Recommended next work (implementation, not more audits)

1. ~~Remove `Win32IDE_private_stubs.cpp` from the shipping target~~ **done** (commented out of `WIN32IDE_SOURCES`).  
2. Add **`cmd`** to `agentic_controller_wiring.cpp` `allowedPrefixes` (and document `AgentToolHandlers::allowedCommands`).  
3. Delete or quarantine **orphaned** win32app TUs, or add a generated “in-target vs on-disk” list to CI so the folder stops lying.  
4. Pick **one** debugger stack and make F5 call it; delete or `#if 0` Sidebar no-ops.  
5. Either Core-init `startAllLSPServers()` or stop advertising clangd-at-boot.  
6. Stop marking FeatureManifest rows `Real` without a self-test that touches I/O.  
7. Keep transcendence names out of user-facing “complete” claims.

---

## 15. Source map (primary files)

| Layer | Paths |
|-------|--------|
| Boot / layout | `src/win32app/main_win32.cpp`, `Win32IDE.cpp`, `Win32IDE_Core.cpp`, `Win32IDE_Window.cpp`, `Win32IDE_Sidebar.cpp`, `Win32IDE_VSCodeUI.cpp` |
| Build graph | root `CMakeLists.txt` (`RAWRXD_BUILD_WIN32IDE`) |
| Catalog (optimistic) | `src/win32app/Win32IDE_FeatureManifest.cpp` |
| Flags (more honest, unlinked) | `src/win32app/FeatureRegistry.cpp` |
| Agent tools | `src/agentic/AgentToolHandlers.cpp`, `src/agentic/agentic_controller_wiring.cpp` |
| Chat send | `Win32IDE_ChatPanel_Ollama.cpp` (native only; stubs removed from CMake) |
| Reverse parser | `src/streamer/LocalStreamReverseParser.hpp/.cpp`, `src/win32app/Win32IDE_StreamLoadDiagnostics.cpp` |
| Theater admission | `CMakeLists.txt` ~L4843–4862 |

---

*Audit produced 2026-08-29 by source inspection of canonical `/workspace/src` and root CMake. Prior reports (`WIN32_IDE_STUB_AUDIT.md` 2026-07-08, FeatureManifest “Phase 33 complete” comments, `RAWRXD_INVENTORY`) were used only as leads, not as answers.*
