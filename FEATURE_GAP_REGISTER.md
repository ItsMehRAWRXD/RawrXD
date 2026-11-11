# FEATURE GAP REGISTER — RawrXD Native IDE

Generated: 2026-11-11  
Canonical: `src/win32app/` (48 files)  
Recoverable: `.kilo/worktrees/thorn-measure/src/win32app/` (634 files not in canonical)

---

## Summary by Category (20 groups)

| # | Category | Canonical | Recoverable | Gap |
|---|----------|-----------|-------------|-----|
| 1 | **Editor Core** | 0/34 | 34 | **ALL MISSING** |
| 2 | **Project & Workspace** | 3/31 | 28 | 90% |
| 3 | **Version Control** | 0/1 | 1 | 100% |
| 4 | **Debugger** | 3/27 | 24 | 89% |
| 5 | **AI Features** | 8/93 | 85 | 91% |
| 6 | **Local Model Management** | 0/6 | 6 | 100% |
| 7 | **Language Support (LSP)** | 0/27 | 27 | 100% |
| 8 | **Extensions / Plugins** | 0/49 | 49 | 100% |
| 9 | **UI/UX Polish** | 2/41 | 39 | 95% |
| 10 | **Collaboration** | 0/36 | 36 | 100% |
| 11 | **Inference Engine** | 0/14 | 14 | 100% |
| 12 | **Context & RAG** | 0/11 | 11 | 100% |
| 13 | **Agent Framework** | 8/93 | 85 | 91% |
| 14 | **Performance & Resource** | 0/14 | 14 | 100% |
| 15 | **Data & State** | 0/12 | 12 | 100% |
| 16 | **Security & Privacy** | 0/8 | 8 | 100% |
| 17 | **Build & Distribution** | 0/12 | 12 | 100% |
| 18 | **Testing & Quality** | 1/11 | 10 | 91% |
| 19 | **Business Infrastructure** | 0/8 | 8 | 100% |
| 20 | **Compliance & Enterprise** | 0/8 | 8 | 100% |

**Total: ~463 missing features across 20 categories**  
**Recoverable from thorn-measure: ~389 files implementing ~320 features**

---

## DETAILED GAP REGISTER

### Category 1: Editor Core (34 features, ALL MISSING)

| ID | Feature | Recoverable File(s) | Lines | Status |
|----|---------|---------------------|-------|--------|
| E01 | Syntax Highlighting (Tree-sitter based) | `Win32IDE_SyntaxHighlight.cpp/h` | 947 | Recoverable |
| E02 | Multi-cursor / Column Selection | `Win32IDE_MultiCursor.cpp/h` | 562 | Recoverable |
| E03 | Minimap | `Win32IDE_Minimap.cpp/h` | 321 | Recoverable |
| E04 | Breadcrumbs | `Win32IDE_Breadcrumbs.cpp/h` | 360 | Recoverable |
| E05 | Outline View | `Win32IDE_OutlinePanel.cpp/h`, `OutlinePanel.h` | 339+ | Recoverable |
| E06 | Sticky Scroll | — | — | Not in thorn-measure |
| E07 | Diff Viewer (inline/side-by-side/3-way) | `Win32IDE_DiffView.cpp/h` | 405 | Recoverable |
| E08 | Large File Handling (10MB+) | — | — | Partial via RichEdit |
| E09 | Split Panes / Detachable Windows | `Win32IDE_DockingPaneManager.cpp/h` | — | Recoverable |
| E10 | Command Palette (fuzzy) | `Win32IDE_CommandPalette.cpp/hpp` | 879 | Recoverable |
| E11 | Quick Open (fuzzy file search) | `Win32IDE_QuickOpen.cpp/h` | — | Recoverable |
| E12 | Code Completion (LSP-driven) | `Win32IDE_CodeCompletion.cpp/h` | — | Recoverable |
| E13 | Inline/Ghost Completion | `Win32IDE_InlineCompletion.cpp/h` | — | Recoverable |
| E14 | Go to Definition | `Win32IDE_GoToSymbol.cpp/h` | 313 | Recoverable |
| E15 | Find All References | `Win32IDE_ReferencesPanel.cpp/h` | — | Recoverable |
| E16 | Symbol Search (workspace-wide) | `Win32IDE_SemanticIndex.cpp/h` | 430 | Recoverable |
| E17 | Workspace Symbols | `Win32IDE_WorkspaceSymbol.cpp/h` | — | Recoverable |
| E18 | Rename Refactoring | `Win32IDE_Refactor.cpp`, `Win32IDE_RenamePreview.cpp/h` | 313+ | Recoverable |
| E19 | Extract Method/Inline/Move/Safe Delete | `Win32IDE_Refactoring.cpp`, `RefactoringEngine.cpp/h` | 313+ | Recoverable |
| E20 | Hover Tooltips | `Win32IDE_HoverTooltips.cpp/h` | — | Recoverable |
| E21 | Signature Help | `Win32IDE_SignatureHelp.cpp/h` | — | Recoverable |
| E22 | Code Lens | `Win32IDE_CodeLens.cpp/h` | — | Recoverable |
| E23 | Inlay Hints | `Win32IDE_InlayHints.cpp/h` | — | Recoverable |
| E24 | Snippet Engine | `Win32IDE_SnippetEngine.cpp/h` | 35116 bytes | Recoverable |
| E25 | Format on Save / Formatter Integration | `format_router.cpp` (src root) | 10083 bytes | Recoverable |
| E26 | Linter Integration | — | — | Not in thorn-measure |
| E27 | Vim/Emacs Keybinding Modes | — | — | Not in thorn-measure |
| E28 | Zen / Distraction-Free Mode | — | — | Not in thorn-measure |
| E29 | Status Bar (git, errors, line/col, encoding) | `Win32IDE_StatusBarActions.cpp` | — | Recoverable |
| E30 | Notifications/Toasts | — | — | Not in thorn-measure |
| E31 | Peek View / Peek Overlay | `Win32IDE_PeekView.cpp/h`, `Win32IDE_PeekOverlay.cpp/h` | — | Recoverable |
| E32 | Call Stack Symbols | `Win32IDE_CallStackSymbols.cpp/h` | — | Recoverable |
| E33 | Go to Line | `Win32IDE_GoToLine.cpp/h` | — | Recoverable |
| E34 | Annotation Overlay | `Win32IDE_AnnotationOverlay.cpp/h`, `AnnotationOverlay.h` | — | Recoverable |

---

### Category 2: Project & Workspace (31 features, 3 present)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| P01 | Multi-root Workspaces | ❌ | `Win32IDE_Project.cpp` |
| P02 | File Explorer with Git Decorators | ❌ | `Win32IDE_Sidebar.cpp` (partial), `Win32IDE_FileIcons.cpp` |
| P03 | File Nesting Rules | ❌ | — |
| P04 | Global Search & Replace (regex, filters) | ❌ | `Win32IDE_SearchPanel.cpp` |
| P05 | Task Runner (npm, cargo, gradle, CMake, Make) | ❌ | `Win32IDE_TaskRunner.cpp`, `Win32IDE_Tasks.cpp`, `Win32IDE_TaskEvents.cpp` |
| P06 | Integrated Terminal (multi-tab, profiles, shell detect) | ⚠️ Partial (`Win32TerminalManager`) | `Win32IDE_TerminalTabs.cpp`, `Win32IDE_TerminalSplit.cpp`, `Win32IDE_TerminalAnsi.cpp`, `Win32IDE_TerminalProfiles.cpp` |
| P07 | Output / Debug / Problems Panels | ⚠️ Partial | `Win32IDE_ProblemsPanel.cpp`, `Win32IDE_CompilerPanel.cpp` |
| P08 | Clickable Error Navigation | ❌ | `Win32IDE_CompilerPanel.cpp` |
| P09 | Project Settings (.vscode-style) | ❌ | `Win32IDE_Settings.cpp/h` |
| P10 | Workspace Symbol Index | ❌ | `Win32IDE_SemanticIndex.cpp` |

---

### Category 3: Version Control (1 feature, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| V01 | Full Git Integration (stage, commit, push, pull, branch, stash, cherry-pick, merge conflict resolution, blame, graph, PR review) | `Win32IDE_Git.cpp/h`, `Win32IDE_GitPanel.cpp` |

---

### Category 4: Debugger (27 features, 3 present)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| D01 | Breakpoints (regular, conditional, logpoint, hit-count) | ⚠️ `BREAKPOINT_MANAGER_INTEGRATION.md` only | `Win32IDE_BreakpointManagerPanel.cpp/hpp`, `BreakpointPropertiesDialog.cpp` |
| D02 | Call Stack, Locals, Watch Expressions | ❌ | `Win32IDE_CallStackSymbols.cpp`, `Win32IDE_DebugWatchFormat.cpp` |
| D03 | Step Over/Into/Out, Run to Cursor | ❌ | `Win32IDE_DebuggerIntegration.cpp/hpp` |
| D04 | Attach to Process / Remote Debug | ❌ | `Win32IDE_DAPServer.cpp/h` |
| D05 | Memory/Register Inspection (C/C++/Rust) | ❌ | `Win32IDE_MemoryView.cpp` |
| D06 | DAP Support | ❌ | `DAPIntegrationBridge.cpp/hpp`, `Win32IDE_DAPServer.cpp/h`, `DapService_test.cpp` |

---

### Category 5: AI Features (93 in thorn-measure, 8 in canonical)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| A01 | Inline Code Completion (Ghost Text) | ⚠️ `Win32IDE_GhostText*` | `Win32IDE_InlineCompletion.cpp`, `Win32IDE_GhostTextOverlay.h`, `GhostTextContextSubscriber.cpp` |
| A02 | Chat Panel (explain, generate, refactor, debug, document) | ⚠️ `Win32IDE_ChatPanel_Ollama.cpp` | `Win32IDE_ChatPanel.cpp`, `Win32IDE_ChatWindow.cpp/h`, `Win32IDE_ChatHistoryPersistence.cpp` |
| A03 | Agent Mode (multi-step tasks) | ⚠️ `Win32IDE_Agentic*` | `Win32IDE_AutonomousAgent.cpp`, `Win32IDE_AutonomousCommunicator.cpp`, `Win32IDE_AgenticPlanningPanel.cpp`, `Win32IDE_AgenticComposerUX.cpp`, `Win32IDE_ProvableAgent.cpp` |
| A04 | Codebase-wide Context (RAG) | ❌ | `Win32IDE_ProjectRagLite.cpp`, `Win32IDE_SemanticIndex.cpp` |
| A05 | @ Mentions (symbols, files, docs) | ❌ | `Win32IDE_ContextMentionParser.cpp` |
| A06 | Terminal Command Generation | ❌ | `Win32IDE_AgenticBrowser.cpp`, `Win32IDE_CommandFlight.cpp` |
| A07 | Multi-model Support (local 7B/13B/70B) | ❌ | `Win32IDE_ModelManager.cpp/h`, `Win32IDE_ModelDropdownProfile.h`, `Win32IDE_SwarmModelSelector.cpp/h` |
| A08 | Custom Instructions per Project | ❌ | `Win32IDE_PromptTemplates.cpp` |
| A09 | Code Review AI | ❌ | `Win32IDE_StaticAnalysisPanel.cpp`, `Win32IDE_SecurityScans.cpp`, `Win32IDE_SecurityDashboard.cpp` |

---

### Category 6: Local Model Management (6 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| M01 | Model Browser (download, delete, organize GGUF/ONNX) | `Win32IDE_ModelDiscovery.cpp`, `Win32IDE_ModelLab.cpp` |
| M02 | Quantization Selector (Q4_K_M, Q5_K_M, Q8_0...) | `Win32IDE_Quantum.cpp`, `Win32IDE_VocabResolver.cpp` |
| M03 | Context Length Config (4K, 8K, 32K, 128K) | `Win32IDE_ModelManager.cpp` |
| M04 | GPU/CPU Scheduling (offload layers, batch, threads) | `Win32IDE_VRAM_Bridge.cpp`, `Win32IDE_Scheduler_Shutdown.cpp` |
| M05 | Model Benchmarking (tokens/sec, memory) | `Win32IDE_BenchmarkMenu.cpp/h`, `BenchmarkMenu.cpp/h` |
| M06 | Model Loader / GGUF Reader | `Win32IDE_GGUF_Reader.cpp`, `Win32IDE_GGUF_V4_Support.cpp`, `Win32IDE_GGUFManifold.cpp/h`, `gguf_loader_masm*.cpp` |

---

### Category 7: Language Support / LSP (27 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| L01 | LSP Client (stdin/stdout, JSON-RPC) | `Win32IDE_LSPClient.cpp`, `AdvancedLSPClient.cpp/h`, `LSPClient.cpp` (src root) |
| L02 | LSP Server Hosting | `Win32IDE_LSPServer.cpp` |
| L03 | Pre-configured Servers (Python, TS/JS, C/C++, Rust, Go, Java, C#, Ruby, PHP, Swift, Kotlin) | `Win32IDE_LanguagePlugin.cpp` |
| L04 | Formatter Integration (prettier, black, rustfmt, clang-format) | `format_router.cpp` |
| L05 | Linter Integration (eslint, pylint, clippy) | — |
| L06 | Snippet Libraries per Language | `Win32IDE_SnippetEngine.cpp` |
| L07 | Semantic Tokens / Highlighting | `Win32IDE_SemanticTokens.cpp/h`, `Win32IDE_SyntaxHighlight.cpp` |
| L08 | Code Actions / Quick Fixes | `Win32IDE_CodeActions.cpp` |
| L09 | Document Symbols / Outline | `Win32IDE_OutlinePanel.cpp` |
| L10 | Workspace Symbols | `Win32IDE_SemanticIndex.cpp` |

---

### Category 8: Extensions / Plugins (49 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| X01 | Extension Marketplace (discover, install, update, disable) | `Win32IDE_ExtensionMarketplace.cpp`, `VSCodeMarketplaceAPI.cpp/hpp`, `VSIXInstaller.hpp` |
| X02 | Extension API (commands, tree views, webviews, status bar, decorations) | `ExtensionAPI_VSCode.cpp/h`, `ExtensionAPI_VSCode_Dispatcher.cpp`, `ExtensionAPI_VSCode_Internal.h` |
| X03 | Extension Isolation (crash one, don't bring down IDE) | `ExtensionSandboxManager.cpp/h`, `ExtensionHost.cpp/h`, `ExtensionHostProcess.cpp/h` |
| X04 | Extension Host (separate process) | `ExtensionHost.cpp/h`, `ExtensionHost_Discovery.cpp`, `ExtensionHostIpcBridge.cpp/hpp` |
| X05 | Extension Manifest Loader | `ExtensionManifestLoader.cpp/h` |
| X06 | Extension Security Check | `ExtensionSecurityCheck.cpp` |
| X07 | Native Plugin Manager | `NativePluginManager.cpp/h` |
| X08 | VS Code Extension Compatibility | `ExtensionAPI_VSCode.cpp`, `Win32IDE_VSCodeExtAPI.cpp` |

---

### Category 9: UI/UX Polish (41 features, 2 present)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| U01 | Custom Themes (light, dark, high contrast, custom CSS) | ❌ | `Win32IDE_Themes.cpp` (1608 lines), `Win32IDE_MonacoThemes.cpp`, `Win32IDE_Tier1Cosmetics.cpp`, `Win32IDE_Tier2Cosmetics.cpp`, `Win32IDE_Tier3Cosmetics.cpp`, `Win32IDE_Tier3Polish.cpp`, `Win32IDE_Tier5Cosmetics.cpp/h` |
| U02 | Font Ligatures, Variable Font Support | ❌ | `Win32IDE_LineEndingSelector.cpp`, `Win32IDE_EmojiSupport.cpp` |
| U03 | Command Palette (fuzzy) | ❌ | `Win32IDE_CommandPalette.cpp/hpp` |
| U04 | Keyboard Shortcut Editor (conflict detection) | ❌ | `Win32IDE_ShortcutEditor.cpp`, `Win32IDE_Accelerators.cpp` |
| U05 | Zen Mode / Distraction-Free | ❌ | — |
| U06 | Status Bar (git, errors, line/col, encoding, lang) | ⚠️ Partial | `Win32IDE_StatusBarActions.cpp`, `StatusBarGitMonitor.cpp/hpp` |
| U07 | Notifications / Toasts | ❌ | `Win32IDE_NotificationPanel.cpp` |
| U08 | Welcome Page | ❌ | `Win32IDE_WelcomePage.cpp` |
| U09 | Settings GUI | ❌ | `Win32IDE_SettingsGUI.cpp`, `settings_dialog.cpp` |
| U10 | Color Picker | ❌ | `Win32IDE_ColorPicker.cpp` |

---

### Category 10: Collaboration (36 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| C01 | Live Share (real-time collaborative editing) | `Win32IDE_Collab.cpp`, `collab_cursor_impl.cpp`, `collab_cursor_production.cpp` |
| C02 | Comments on Code (inline discussions) | `Win32IDE_AnnotationOverlay.cpp` |
| C03 | Pair Programming Mode | — |
| C04 | Voice Assistant / Automation | `VoiceAssistantWorker.cpp/hpp`, `VoiceAutomation_Panel.cpp`, `Win32IDE_VoiceAssistantPanel.cpp`, `Win32IDE_VoiceChat.cpp` |
| C05 | Screen Pilot / Remote Control | `ScreenPilotModelHub.cpp/h`, `Win32IDE_AgenticBrowser.cpp` |
| C06 | CRDT / Conflict Resolution | `rawrxd_collab_crdt_impl.cpp` |
| C07 | RTP / Real-time Protocol | `rtp_protocol_bridge.cpp`, `rtp_protocol_impl.cpp`, `rtp_protocol_production.cpp` |

---

### Category 11: Inference Engine (14 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| I01 | Local LLM Runtime (llama.cpp / custom backend) | `cpu_inference_engine_impl.cpp` (src root), `Win32IDE_AIBackend.cpp`, `Win32IDE_AIFeatures.cpp/h`, `Win32IDE_AIFeatures_Real.cpp` |
| I02 | Multi-backend (Vulkan, CUDA, Metal, DirectML, CPU AVX2/512/NEON) | `vulkan_compute.cpp` (src root), `VulkanRenderer.cpp`, `Win32IDE_VulkanRenderer.cpp`, `Win32IDE_GPUIntegration.exe` |
| I03 | Streaming Token Generation | `Win32IDE_StreamingUX.cpp` |
| I04 | Speculative Decoding | `SpeculativeOptimizer.cpp/h`, `Win32IDE_SpeciatorEngine.cpp`, `Win32IDE_SpeciatorEvents.cpp` |
| I05 | Continuous Batching | — |
| I06 | KV-Cache Management | `Win32IDE_KVCacheCleanup.cpp`, `Win32IDE_KVApertureProbe.cpp/h`, `Win32IDE_KVApertureProbeGate.cpp` |
| I07 | GGUF Parser | `GGUFLoader.cpp`, `streaming_gguf_loader.cpp`, `gguf.cpp` (src root) |
| I08 | ONNX Runtime Integration | — |

---

### Category 12: Context & RAG (11 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| R01 | Codebase Indexing (AST, symbol graph, chunking) | `Win32IDE_SemanticIndex.cpp`, `indexer.cpp` (src/context), `SourceFileRegistry.cpp/h`, `FileRegistry_*.cpp` |
| R02 | Embedding Model (sentence-transformer) | `semantic_store.cpp` (src/context) |
| R03 | Vector Database (sqlite-vss, faiss, chroma) | — |
| R04 | Incremental Indexing | `Win32IDE_FileSystemEvents.cpp` |
| R05 | Context Assembly (prioritize, token budget) | `Win32IDE_ContextGovernor.cpp/h`, `Win32IDE_ProjectRagLite.cpp` |
| R06 | Repository Map Generation | `RawrXD_SymbolEngine.cpp`, `Win32IDE_PDBSymbols.cpp` |

---

### Category 13: Agent Framework (93 features in thorn-measure, 8 in canonical)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| AF01 | Tool/Function Calling (shell, read, edit, search) | ⚠️ `Win32IDE_AgentCommands.cpp` | `Win32IDE_AgentExecutor.cpp/h`, `Win32IDE_AgentHistory.cpp`, `Win32IDE_ToolActionStatus.cpp` |
| AF02 | Planning & Execution Loop | ❌ | `Win32IDE_AutonomousLoop.h`, `Win32IDE_Phase16_AgenticController.cpp/h`, `Win32IDE_PlanExecutor.cpp` |
| AF03 | State Machine (pending, running, waiting, done, error) | ❌ | `Win32IDE_AgentStepTimeline.cpp/h`, `HeadlessAgentsJson.hpp`, `HeadlessAgentsRing.hpp` |
| AF04 | Sandboxing (restrict AI deletions/modifications) | ❌ | `ExtensionSandboxManager.cpp/h`, `Win32IDE_ExecutionGovernor.cpp`, `Win32IDE_ExecutionTruth.cpp/h` |
| AF05 | Undo Stack for AI Edits | ❌ | `Win32IDE_AgentHistory.cpp` |
| AF06 | Approval Gates (run command? edit file?) | ❌ | `Win32IDE_ConsentPrompt.cpp` |
| AF07 | Agentic Bridge / Loop Bridge | ⚠️ `Win32IDE_AgenticBridge.cpp`, `Win32IDE_AgenticLoopBridge.cpp` | `Win32IDE_AgenticIntegration.cpp/h`, `Win32IDE_AgentBridge.cpp/hpp`, `Win32IDE_AgentBridge_Init.cpp/hpp` |

---

### Category 14: Performance & Resource Management (14 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| PR01 | Memory Budget Enforcement | `Win32IDE_MemoryStats.cpp`, `Win32IDE_HeapHardening.cpp` |
| PR02 | GPU Memory Monitoring (dynamic offload) | `Win32IDE_VRAM_Bridge.cpp`, `Win32IDE_LayerEviction.cpp` |
| PR03 | Background Worker Threads (indexing, model loading) | `Win32IDE_IOCPFileWatcher.cpp`, `ai_workers_queue.cpp` |
| PR04 | Lazy Initialization (don't load models until needed) | `Win32IDE_InitSequence.cpp` |
| PR05 | Swap/Paging Awareness | `Win32IDE_PageFaultHandler.cpp` |
| PR06 | Battery Awareness | — |
| PR07 | Performance Profiler | `PerformanceProfiler.cpp/h`, `Win32IDE_PerfTelemetry.cpp`, `Win32IDE_Telemetry.cpp`, `Win32IDE_TelemetryEvents.cpp`, `Win32IDE_TelemetryExport.cpp`, `Win32IDE_TelemetryDashboard.cpp`, `Win32IDE_TelemetryPanel.cpp`, `IDE_Telemetry.cpp/hpp` |

---

### Category 15: Data & State (12 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| DS01 | Session Persistence (open files, cursors, terminal history, chat history) | `Win32IDE_Session.cpp`, `Win32IDE_ChatHistoryPersistence.cpp`, `host_persistence_test.cpp` |
| DS02 | Project Settings (.vscode-style) | `Win32IDE_Settings.cpp/h` |
| DS03 | User Preferences (cross-workspace, synced/portable) | `Win32IDE_Settings.cpp`, `cloud_settings_dialog.cpp` (src/ide) |
| DS04 | Crash Recovery (auto-save, restore unsaved) | `rawr_crash_handler.cpp`, `Win32IDE_CrashReporter.cpp`, `Win32IDE_Heartbeat_Shutdown.cpp`, `Win32IDE_Infinity_Shutdown.cpp`, `Win32IDE_Scheduler_Shutdown.cpp` |
| DS05 | Startup Banner | `Win32IDE_StartupBanner.cpp` |

---

### Category 16: Security & Privacy (8 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| SP01 | Zero Network Requirement for Core AI | (Architecture - not a file) |
| SP02 | Optional Cloud Fallback (opt-in) | `Win32IDE_AirgappedEnterprise.cpp`, `hybrid_cloud_manager.cpp` (src) |
| SP03 | Code Execution Sandbox | `ExtensionSandboxManager.cpp`, `Win32IDE_ExecutionGovernor.cpp` |
| SP04 | Secret Scanning | `Win32IDE_SecurityScans.cpp`, `Win32IDE_SecurityDashboard.cpp`, `Win32IDE_SecurityReport.cpp` |
| SP05 | Telemetry (strict opt-in, anonymized) | `Win32IDE_Telemetry.cpp`, `IDE_Telemetry.cpp` |
| SP06 | AES-GCM + Hash-chained Audit | `Win32IDE_Attestation.cpp`, `production/` (src) |
| SP07 | License Management / Activation | `Win32IDE_LicenseCreator.cpp` |

---

### Category 17: Build & Distribution (12 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| BD01 | Cross-platform Builds (Windows MSI/EXE, macOS DMG, Linux AppImage/DEB/RPM/Flatpak) | — |
| BD02 | Auto-updater (delta updates, rollback) | — |
| BD03 | Code Signing (Windows EV, macOS notarization, Linux GPG) | — |
| BD04 | Installer (silent install, portable mode) | `Win32IDE_DownloadsPanel.cpp/h` |
| BD05 | Crash Reporter (minidump, optional upload) | `Win32IDE_CrashReporter.cpp` |

---

### Category 18: Testing & Quality (11 features, 1 present)

| ID | Feature | Canonical | Recoverable |
|----|---------|-----------|-------------|
| TQ01 | Unit Test Suite (core editor, AI, agent) | ❌ | `Win32IDE_EnterpriseStressTests.cpp`, `*_test.cpp` (many) |
| TQ02 | Integration Tests (LSP, debugger, model loading) | ❌ | `Win32IDE_DebuggerIntegration_test.cpp`, `NotebookLSPTest.cpp`, `AdvancedLSPTest.cpp` |
| TQ03 | Performance Benchmarks (startup, file open, tokens/sec) | ❌ | `Win32IDE_BenchmarkMenu.cpp`, `BenchmarkMenu.cpp` |
| TQ04 | Accessibility Testing | ❌ | — |
| TQ05 | Localization Framework (i18n) | ❌ | — |

---

### Category 19: Business Infrastructure (8 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| BI01 | License Management (activation, floating, trials) | `Win32IDE_LicenseCreator.cpp` |
| BI02 | Payment Processing / Subscription | — |
| BI03 | Usage Analytics (feature adoption, crash rates) | `Win32IDE_Telemetry.cpp` |
| BI04 | Support System (ticketing, KB, forum) | — |
| BI05 | Documentation (user, API, troubleshooting) | — |

---

### Category 20: Compliance & Enterprise (8 features, 0 present)

| ID | Feature | Recoverable |
|----|---------|-------------|
| CE01 | SOC 2 / ISO 27001 Readiness | `Win32IDE_AuditDashboard.cpp`, `Win32IDE_Attestation.cpp` |
| CE02 | SSO / SAML / OIDC Integration | — |
| CE03 | Audit Logging | `Win32IDE_AuditDashboard.cpp` |
| CE04 | Air-gapped Deployment | `Win32IDE_AirgappedEnterprise.cpp` |
| CE05 | Proxy Support | — |

---

## IMPLEMENTATION PLAN: BATCHES OF 15

### Batch 1: Core Editor (15 features)
E01 Syntax Highlighting, E02 Multi-cursor, E03 Minimap, E04 Breadcrumbs, E05 Outline View, E07 Diff Viewer, E10 Command Palette, E11 Quick Open, E12 Code Completion, E13 Inline Completion, E14 Go to Definition, E15 Find References, E16 Workspace Symbols, E18 Rename Refactoring, E20 Hover Tooltips

### Batch 2: LSP/Language (15 features)
L01 LSP Client, L02 LSP Server, L03 Language Plugins, L04 Formatter Integration, L06 Snippet Engine, L07 Semantic Tokens, L08 Code Actions, L09 Document Symbols, L10 Workspace Symbols, E17 Symbol Search, E19 Extract Method, E21 Signature Help, E22 Code Lens, E23 Inlay Hints, E24 Snippet Engine

### Batch 3: AI/Agent (15 features)
A01 Ghost Text, A02 Chat Panel, A03 Agent Mode, A04 RAG Context, A05 @ Mentions, A06 Terminal Commands, A07 Multi-model, A08 Custom Instructions, A09 Code Review AI, AF01 Tool Calling, AF02 Planning Loop, AF03 State Machine, AF04 Sandboxing, AF05 Undo Stack, AF06 Approval Gates

### Batch 4: Project/Workspace/Git/Terminal/Themes (15 features)
P01 Multi-root, P02 File Explorer + Git Decorators, P04 Global Search, P05 Task Runner, P06 Terminal Tabs/Split/Profiles, P07 Output/Debug/Problems Panels, P08 Error Navigation, P09 Project Settings, V01 Git Integration, U01 Themes, U03 Command Palette (done B1), U04 Shortcut Editor, U06 Status Bar, U09 Settings GUI

### Batch 5: Extensions/Inference/ModelMgmt (15 features)
X01 Marketplace, X02 Extension API, X03 Isolation, X04 Extension Host, X05 Manifest Loader, X06 Security Check, I01 LLM Runtime, I02 Multi-backend, I03 Streaming, I04 Speculative Decoding, I06 KV-Cache, I07 GGUF Parser, M01 Model Browser, M02 Quant Selector, M06 Model Loader

### Batch 6: Debugger/Collab/Context/RAG (15 features)
D01 Breakpoints, D02 Call Stack/Locals/Watch, D03 Step Debugging, D04 Attach/Remote, D05 Memory Inspection, D06 DAP, C01 Live Share, C02 Code Comments, C04 Voice, R01 Indexing, R02 Embeddings, R04 Incremental Index, R05 Context Assembly, R06 Repo Map, AF07 Agentic Bridge

### Batch 7: Performance/Security/Enterprise/Build (15 features)
PR01 Memory Budget, PR02 GPU Monitoring, PR03 Background Workers, PR04 Lazy Init, PR05 Swap Awareness, PR07 Profiler, SP02 Cloud Fallback, SP03 Sandbox, SP04 Secret Scanning, SP05 Telemetry Opt-in, SP06 Audit, SP07 License, BD04 Installer, BD05 Crash Reporter, CE04 Air-gapped

---

## RECOVERY SOURCE MAP

All recoverable files are in:
```
F:\rawrxd\.kilo\worktrees\thorn-measure\src\win32app\
```

Key header files to merge:
- `Win32IDE.h.clean` (50KB) - clean header
- `Win32IDE_temp.h` (307KB) - full declarations
- `Win32IDE_Commands.h` (21KB)
- `Win32IDE_Types.h` (14KB)
- `Win32IDE_ComponentManagers.h` (5KB)

---

## NEXT ACTIONS

1. **Create Batch 1 directory structure** in canonical `src/win32app/`
2. **Copy 15 Batch 1 files** from thorn-measure
3. **Update CMakeLists.txt** to include new sources
4. **Configure and build** with `RAWRXD_BUILD_WIN32IDE=ON`
5. **Verify compile** - fix any missing deps/includes
6. **Repeat for Batch 2-7**