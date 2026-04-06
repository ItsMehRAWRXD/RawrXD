# RawrXD Reverse Audit — Unwired Agentic / IDE / Model Features
**Date:** 2026-04-05  
**Method:** Static analysis of 2,628 source files across `d:\rawrxd\src\`  
**Sources:** `Win32IDE_FeatureManifest.cpp` (174 features, 4 IDE variants), `auto_feature_stub_impl.cpp` (557 stubs), `ssot_handlers.cpp` (153 `__rawrxd_missing_stub_` declarations), `missing_handler_stubs.cpp` (currently empty — stubs evicted), direct source grep.

---

## Summary Statistics

| Category | Count |
|---|---|
| Win32IDE features: **REAL** (wired) | 67 |
| Win32IDE features: **PARTIAL** (partial wiring) | 16 |
| Win32IDE features: **MISSING** (not wired) | 91 |
| `auto_feature_stub_impl.cpp` pure stubs | 286 |
| `auto_feature_stub_impl.cpp` CS stubs (same body, renamed) | 271 |
| `ssot_handlers.cpp` `__rawrxd_missing_stub_` forwards | 153 |
| `missing_handler_stubs.cpp` body | **empty** (evicted) |

---

## Section A — PARTIAL Features (Win32IDE — have code, incomplete)

These have some wiring but are flagged `FeatureStatus::Partial` in the manifest:

| Feature ID | Name | Gap |
|---|---|---|
| `file.modelFromURL` | Model from URL | Dialog opens, download/verification not complete |
| `theme.dracula` | Dracula Theme | Not all UI elements themed |
| `theme.16themes` | 16 Built-in Themes | Several themes missing `COLORREF` palette fills |
| `syntax.asm` | Assembly Highlighting | Partial — `RichEdit` path only, no Monaco path |
| `syntax.6languages` | 6 Language Support | Only C/C++/Python; ASM/Rust/Go partial |
| `terminal.split` | Split Terminal | Panel created, stdin routing not wired |
| `agent.viewTools` | View Agent Tools | Tool list enumerates but doesn't show live status |
| `agent.memory` | Agent Memory | `ContextBuf_BuildPrompt` wired; persistence not saved across sessions |
| `agent.history` | Agent History | `AgentHistory` stored; no export/replay UI |
| `debug.start` | Start Debugger | Launch path works; `CDB` attach path partial |
| `debug.breakpoint` | Set Breakpoint | Conditional BP dialog exists; hardware BP not available |
| `streaming.ghostText` | Ghost Text Completion | Renders in RichEdit; cancelled on cursor move only, no debounce gate |
| `subagent.spawn` | Spawn Sub-Agent | `executeSubagent()` works; no output stream routing to separate pane |
| `llm.multiEngine` | Multi-Engine Router | Ensemble disabled by default; `LLMRouter` pass-through when disabled |
| `llm.backendSwitch` | Backend Switcher | Works for Ollama/local; OpenAI backend handler is stub |
| `server.local` | Local Inference Server | HTTP server runs; capability matching + fallback chains not wired |

---

## Section B — MISSING Features (Win32IDE — not wired at all)

### B1 — Agentic / Agent

| Feature ID | Name | Notes |
|---|---|---|
| `agent.autonomous` | Autonomous Agent | Auto-loop flag toggled but `setContextWindow()` not wired to `AutonomousAgenticPipelineCoordinator` |
| `agent.failureDetection` | Failure Detection | `g_failureIntelligence` object exists; recovery execution path not triggered from UI |
| `agent.failureIntelligence` | Failure Intelligence | Recovery plans generated; no UI gate to execute them |
| `plan.executor` | Plan Executor | `🛑 Plan Orchestrator stop requested (not yet implemented)` — stop/pause not wired |
| `subagent.chain` | Prompt Chain | `handleSubagentChain` — pure stub in `auto_feature_stub_impl.cpp` |
| `subagent.swarm` | HexMag Swarm | `handleSubagentSwarm` — pure stub |
| `subagent.todoList` | Agent Todo List | Manifest: Missing; but `onSubAgentTodoList()` partially exists in Commands.cpp — not in manifest route |
| `exec.governor` | Execution Governor | `handleGovStatus/TaskList/KillAll` — all `__rawrxd_missing_stub_` |
| `autonomy.rateLimit` | Rate Limiter | No rate limiter wired to autonomous loop |

### B2 — LSP

All LSP features are **MISSING** in Win32IDE:

| Feature ID | Name | SSOT Stub? |
|---|---|---|
| `lsp.client` | LSP Client | `__rawrxd_missing_stub_handleLspClearDiag/Configure/Restart/SaveConfig/SymbolInfo` |
| `lsp.server` | LSP Server | Same |
| `lsp.server.completion` | Completion Provider | Missing |
| `lsp.server.definition` | Go-to-Definition | Missing |
| `lsp.server.diagnostics` | Diagnostics Bridge | Missing |
| `lsp.server.docSymbol` | Document Symbols | Missing |
| `lsp.server.hover` | Hover Provider | Missing |
| `lsp.server.index` | Symbol Indexer | Missing |
| `lsp.server.references` | Find References | Missing |
| `lsp.server.semanticTokens` | Semantic Tokens | Missing |
| `lsp.server.stdio` | Stdio Subprocess | Missing |
| `lsp.server.wkspSymbol` | Workspace Symbols | Missing |
| `lsp.aiBridge` | LSP ↔ AI Bridge | Missing |
| `semantic.goto` | Semantic Go-to-Def | Missing |
| `semantic.hierarchy` | Type Hierarchy | Missing |
| `semantic.index` | Index File | Missing |
| `semantic.references` | Semantic Find Refs | Missing |
| `semantic.search` | Search Symbols | Missing |
| `annotations.inline` | Inline Annotations | Missing |

### B3 — Debugger

| Feature ID | Name | SSOT Stub? |
|---|---|---|
| `debug.nativeEngine` | Native Debug Engine | `handleDbgAttach/Detach/Launch/Kill` — all `__rawrxd_missing_stub_` |
| `debug.step` | Step Over | `handleDbgStepOver/StepInto/StepOut` — missing stubs |
| — | Breakpoints (full) | `handleDbgAddBp/ClearBps/EnableBp/RemoveBp/ListBps` — missing stubs |
| — | Memory View | `handleDbgMemory/SearchMemory` — missing stubs |
| — | Registers | `handleDbgRegisters/SetRegister` — missing stubs |
| — | Threads/Stack | `handleDbgThreads/Stack/SwitchThread` — missing stubs |
| — | Watch/Evaluate | `handleDbgAddWatch/Evaluate` — missing stubs |
| — | Disasm in Debugger | `handleDbgDisasm` — missing stub |
| — | Symbol Path | `handleDbgSymbolPath` — missing stub |
| — | Modules List | `handleDbgModules` — missing stub |

### B4 — Reverse Engineering

| Feature ID | Name | Status |
|---|---|---|
| `re.analyze` | PE Analysis | `handleRevengAnalyze` — pure stub |
| `re.cfg` | Control Flow Graph | `handleRevengCfg` — pure stub |
| `re.compile` | MASM Compile | `handleRevengCompile` — pure stub |
| `re.dataFlow` | Data Flow Analysis | `handleRevengDataFlow` — pure stub |
| `re.demangle` | Demangle Symbols | `handleRevengDemangle` — pure stub |
| `re.detectVulns` | Detect Vulnerabilities | `handleRevengDetectVulns` — pure stub |
| `re.disasm` | Disassembly | `handleRevengDisasm/RecursiveDisasm` — pure stubs |
| `re.dumpbin` | DumpBin | `handleRevengDumpbin` — pure stub |
| `re.exportGhidra` | Export to Ghidra | Pure stub |
| `re.exportIDA` | Export to IDA | Pure stub |
| `re.functions` | Function List | `handleRevengFunctions` — pure stub |
| `re.ssa` | SSA Lifting | `handleRevengSsa` — pure stub |
| `re.typeRecovery` | Type Recovery | `handleRevengTypeRecovery` — pure stub |
| `decomp.d2dView` | Direct2D Decompiler | Missing |
| `decomp.syncSelection` | Synchronized Selection | Missing |
| `decomp.syntaxColor` | Decompiler Syntax Coloring | Missing |
| `decomp.varRename` | Variable Rename (SSA) | Missing — `handleRevengDecompRename` stub |

### B5 — ASM Panel

| Feature ID | Name | Status |
|---|---|---|
| — | Analyze Block | `handleAsmAnalyzeBlock` — `__rawrxd_missing_stub_` |
| — | Call Graph | `handleAsmCallGraph` — missing stub |
| — | Clear Symbols | `handleAsmClearSymbols` — missing stub |
| — | Data Flow | `handleAsmDataFlow` — missing stub |
| — | Detect Convention | `handleAsmDetectConvention` — missing stub |
| — | Find Refs | `handleAsmFindRefs` — missing stub, also pure stub `handleAsmFindLabelRefs` |
| — | Goto Label | `handleAsmGoto/GotoLabel` — missing stub |
| — | Instruction Info | `handleAsmInstructionInfo` — missing stub |
| — | Parse | `handleAsmParse/ParseSymbols` — missing stub |
| — | Register Info | `handleAsmRegisterInfo` — missing stub |
| — | Sections | `handleAsmSections/ShowSections/ShowSymbolTable` — stubs |
| — | Show Call Graph | `handleAsmShowCallGraph` — pure stub |
| — | Show Data Flow | `handleAsmShowDataFlow` — pure stub |

### B6 — Model / Inference

| Feature ID | Name | Status |
|---|---|---|
| `file.modelUnified` | Unified Model Load | Manifest: Missing; but `openModelUnified()` **does exist** in `Win32IDE.cpp:9671` — manifest out of date |
| `file.quickLoad` | Quick Load Model | Same — `quickLoadGGUFModel()` exists in `Win32IDE.cpp:8794` — manifest out of date |
| — | Model List | `handleModelList` — `__rawrxd_missing_stub_` |
| — | Model Unload | `handleModelUnload` — missing stub |
| — | Model Quantize | `handleModelQuantize` — missing stub |
| — | Model Finetune | `handleModelFinetune` — missing stub |
| — | Embedding Encode | `handleEmbeddingEncode` — missing stub |
| — | Multi-Response Engine | `handleMultiResp*` (10 handlers) — all missing stubs |
| `multi.response` | Multi-Response Engine | Full block: Generate, Compare, SelectPreferred, SetMax, ShowLatest, ShowPrefs, ShowStats, ShowStatus, ShowTemplates, ToggleTemplate — all missing stubs |

### B7 — Router / Backend

| Feature ID | Name | Status |
|---|---|---|
| — | Router Capabilities | `handleRouterCapabilities/Decision/Fallbacks/ShowStatus/WhyBackend` — pure stubs |
| — | Router Ensemble | `handleRouterEnsembleEnable/Disable/Status` — missing stubs |
| — | Router Pin/Unpin | `handleRouterPinTask/UnpinTask/ShowPins` — missing stubs |
| — | Router Simulate | `handleRouterSimulate/SimulateLast` — missing stubs |
| — | Router Heat Map | `handleRouterShowHeatmap` — missing stub |
| — | Router Cost Stats | `handleRouterShowCostStats` — missing stub |
| — | Router Route Prompt | `handleRouterRoutePrompt` — missing stub |
| — | Router Set Policy | `handleRouterSetPolicy/SaveConfig` — missing stubs |
| `llm.backendSwitch` (OpenAI) | Switch to OpenAI | `handleBackendSwitchOpenai` — pure stub |

### B8 — Vision / Multimodal

| Feature ID | Name | Status |
|---|---|---|
| `vision.analyzeDiagram` | Analyze Diagram | Missing |
| `vision.describe` | Describe Image | Missing |
| `vision.encode` | Encode Image | `handleEmbeddingEncode/VisionAnalyzeImage` — missing stubs |
| `vision.extractCode` | Extract Code from Screenshot | Missing |
| `vision.load` | Load Vision Model | Missing |
| — | Voice PTT | `handleVoicePTT` — pure stub |

### B9 — WebView2 / Monaco

All Monaco/WebView2 features are **MISSING** in Win32IDE:

| Feature ID | Name |
|---|---|
| `webview2.container` | WebView2 Container |
| `webview2.devtools` | Monaco DevTools |
| `webview2.monaco` | Monaco Editor Integration |
| `webview2.msgbridge` | C++/JS Message Bridge |
| `webview2.sync` | Editor Content Sync |
| `webview2.themes` | Monaco Theme Bridge |
| `webview2.zoom` | Monaco Zoom Control |

### B10 — UI Panels / Views

| Feature ID | Name | Status |
|---|---|---|
| `ui.chatPanel` | Chat Panel | Missing in manifest; Win32IDE does have a chat pane but not manifest-wired |
| `ui.chatRenderer` | Chat Message Renderer | Missing |
| `ui.toolStatus` | Tool Action Status | Missing |
| `view.floatingPanel` | Floating Panel | Missing |
| `view.minimap` | Toggle Minimap | Missing |
| `view.moduleBrowser` | Module Browser | `handleModulesExport/Import/Refresh` — pure stubs |
| `view.secondarySidebar` | Secondary Sidebar | Missing |
| `view.themeEditor` | Theme Editor | Missing |
| `swarm.panel` | Swarm Panel | `handleSwarm*` (16 handlers) — all pure stubs |
| `telemetry.perf` | Performance Telemetry | `handleTelemetry*` — stubs; `Metrics.cpp` has 2 explicit `TODO: Implement` |

### B11 — Hotpatch

| Feature ID | Name | Status |
|---|---|---|
| `hotpatch.byteLevel` | Byte-Level Hotpatch | `handleHotpatchByteApply/Search` — pure stubs |
| `hotpatch.memory` | Memory Hotpatch | `handleHotpatchMemoryApply/Revert` — pure stubs |
| `hotpatch.panel` | Hotpatch Panel UI | `handleHotpatchShowStatus/ShowEventLog/ShowProxyStats` — stubs |
| `hotpatch.server` | Server Hotpatch | `handleHotpatchServerAdd/Remove` — stubs |
| `hotpatch.unified` | Unified Hotpatch Mgr | Pure stub |
| — | Proxy Bias/Rewrite/Terminate/Validate | All pure stubs |
| — | Preset Load/Save | Pure stubs |
| — | Reset Stats | Pure stub |
| — | Toggle All | Pure stub |

### B12 — Plugin System

| Feature ID | Name | Status |
|---|---|---|
| — | Plugin Configure | `handlePluginConfigure` — missing stub |
| — | Plugin Load | `handlePluginLoad` — missing stub |
| — | Plugin Refresh | `handlePluginRefresh` — missing stub |
| — | Plugin Scan Dir | `handlePluginScanDir` — missing stub |
| — | Plugin Show Panel | `handlePluginShowPanel` — missing stub |
| — | Plugin Show Status | `handlePluginShowStatus` — missing stub |
| — | Plugin Toggle Hotload | `handlePluginToggleHotload` — missing stub |
| — | Plugin Unload / Unload All | Missing stubs |
| `security.pluginSig` | Plugin Signature | Missing |
| `security.updateSig` | Update Signature | Missing |
| — | Marketplace Install/List | `handleMarketplaceInstall/List` — missing stubs |

### B13 — Headless / Batch Variants

| Feature ID | Name | Status |
|---|---|---|
| `headless.batch` | Headless Batch Mode | Missing in Win32IDE (by design, but untested) |
| `headless.json` | JSON Structured Output | Missing |
| `headless.mode` | Headless Mode | Missing |
| `headless.outputsink` | IOutputSink Interface | Missing |
| `headless.repl` | Headless REPL | Missing |
| `headless.server` | Headless HTTP Server | Missing |
| `headless.singleshot` | Headless Single-Shot | Missing |

### B14 — Replay / Session

| Feature ID | Name | Status |
|---|---|---|
| — | Deterministic Replay | `handleReplayCheckpoint/ExportSession/ShowLast/Status` — all missing stubs |
| `DeterministicReplayEngine.cpp` exists | — | Compiled but no UI route to trigger it |

### B15 — Hybrid AI Analysis

| Feature ID | Name | Status |
|---|---|---|
| — | Hybrid Analyze File | `handleHybridAnalyzeFile` — missing stub |
| — | Hybrid Annotate Diag | `handleHybridAnnotateDiag` — missing stub |
| — | Hybrid Auto Profile | `handleHybridAutoProfile` — missing stub |
| — | Hybrid Complete | `handleHybridComplete` — missing stub |
| — | Hybrid Correction Loop | `handleHybridCorrectionLoop` — missing stub |
| — | Hybrid Diagnostics | `handleHybridDiagnostics` — missing stub |
| — | Hybrid Explain Symbol | `handleHybridExplainSymbol` — missing stub |
| — | Hybrid Semantic Prefetch | `handleHybridSemanticPrefetch` — missing stub |
| — | Hybrid Smart Rename | `handleHybridSmartRename` — missing stub |
| — | Hybrid Stream Analyze | `handleHybridStreamAnalyze` — missing stub |
| — | Hybrid Symbol Usage | `handleHybridSymbolUsage` — missing stub |
| — | Hybrid Status | `handleHybridStatus` — missing stub |

---

## Section C — Specific Agentic Code Gaps

These are **intra-function** gaps found by direct source inspection:

| File | Line | Gap |
|---|---|---|
| `Win32IDE_AgentCommands.cpp` | 483 | `TODO: add setContextWindow()` to `AutonomousAgenticPipelineCoordinator` — context window not propagated |
| `Win32IDE_AgentCommands.cpp` | 1072 | `🛑 Plan Orchestrator stop requested (not yet implemented)` — stop/abort the autonomous loop does nothing |
| `Win32IDE_AgenticBridge.cpp` | 527 | `TODO: add recordLatency to PerformanceMonitor when timing infra lands` — latency not tracked |
| `agentic/Metrics.cpp` | 76 | `TODO: Implement histogram buckets` — Prometheus histogram bins missing |
| `agentic/Metrics.cpp` | 139 | `TODO: Implement HTTP server for Prometheus scraping` — `/metrics` endpoint not served |
| `agentic_planning_orchestrator.cpp` | 689 | `combined = "No-op step: "` — no-op plan steps silently succeed instead of failing |
| `agent_workflow_orchestrator.cpp` | 710 | `execOk = true; // no-op task` — no-op tasks short-circuit to success |
| `agentic/ToolRegistry.cpp` | 89 | Comment: `stubs — real implementations wire into engine` — ToolRegistry dispatch is present but marked stub-origin |

---

## Section D — Outstanding `__rawrxd_missing_stub_` Declarations with No Body

`ssot_handlers.cpp` forward-declares 153 functions as `__rawrxd_missing_stub_handleXxx`. `missing_handler_stubs.cpp` (the file that was supposed to provide them) now contains only `ensureMissingHandlerStubsLinked(){}`. These are mapped via `/alternatename` linker directives in `Win32IDE_SubAgent.cpp` to a universal stub returning `ok("stub")`.

**Key groups with no real implementation anywhere:**

- All 12 `handleDbg*` variants (full debugger control path)
- All 9 `handleHybrid*` variants 
- All 10 `handleMultiResp*` variants
- All 8 `handleRouter*` (pin/unpin/simulate/heatmap/cost)
- All 5 `handlePlugin*` variants
- All 4 `handleReplay*` variants
- `handleVisionAnalyzeImage`, `handleEmbeddingEncode`
- `handleGovernorSetPowerLevel`, `handleGovernorStatus`
- `handleModelList`, `handleModelUnload`, `handleModelQuantize`, `handleModelFinetune`

---

## Section E — Manifest Inaccuracies (Manifest says Missing, code exists)

| Feature ID | Manifest Status | Reality |
|---|---|---|
| `file.modelUnified` | Missing | `Win32IDE.cpp:9671` — `openModelUnified()` fully implemented |
| `file.quickLoad` | Missing | `Win32IDE.cpp:8794` — `quickLoadGGUFModel()` implemented |
| `subagent.todoList` | Missing | `Win32IDE_AgentCommands.cpp:152` + `Win32IDE_SubAgent.cpp:326` — both implement `onSubAgentTodoList()` |
| `ui.chatPanel` | Missing | Chat pane exists and is used heavily but not manifest-registered |

---

## Priority Tiers for Wiring

### Tier 1 — High Impact, Low Effort (plumbing already exists)
1. **Plan Orchestrator Stop** — just needs `m_planOrchestrator->requestStop()` call at line 1072
2. **setContextWindow()** — add method to `AutonomousAgenticPipelineCoordinator` and call at line 483
3. **Manifest correction** — update `file.modelUnified`, `file.quickLoad`, `subagent.todoList`, `ui.chatPanel` to `Real`
4. **Latency recording** — `PerformanceMonitor::recordLatency()` already exists in telemetry; wire at line 527
5. **Model List** — `handleModelList` can enumerate `m_backendSwitcher->getAvailableModels()`

### Tier 2 — Medium Effort (infrastructure present)
1. **Router handlers** (Capabilities, Decision, Fallbacks, Why) — `Win32IDE_LLMRouter.cpp` has the data
2. **Swarm Panel** — `SwarmOrchestrator` and `swarm_orchestrator` classes exist; need UI wiring
3. **Plugin System** — `plugin_system/` dir exists; needs SSOT handlers wired
4. **Agent Memory persistence** — `ContextBuf_*` MASM ring buffer wired; needs file serialization
5. **Replay Engine** — `DeterministicReplayEngine.cpp` (28KB) exists; needs replay/checkpoint UI commands

### Tier 3 — High Effort (build the feature first)
1. **LSP full stack** — 12 capabilities all missing; server infrastructure in `src/lsp/` but not wired to Win32IDE
2. **Monaco/WebView2** — 7 features all missing; requires WebView2 runtime integration
3. **Debug engine full** — 14+ missing handlers; `CDB` bridge exists but not routed
4. **Vision/Multimodal** — vision infra in `src/vision/` but no Win32IDE dispatch
5. **Prometheus HTTP endpoint** — `Metrics.cpp:139` TODO; needs embedded HTTP server
6. **Hybrid AI Analysis** — 12 missing handlers; `hybrid_analysis` infrastructure present in agentic
