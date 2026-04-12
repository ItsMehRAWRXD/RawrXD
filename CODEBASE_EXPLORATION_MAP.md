# RawrXD Codebase Exploration Map
**Generated**: April 10, 2026  
**Scope**: Complete inventory of stubs, modules, build config, and architecture  

---

## PART 1: STUBS & PLACEHOLDERS

### 1. Ghost Text Suggestions
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/ghost_text_renderer.h](src/ghost_text_renderer.h) - Header stub
- [src/ghost_text_renderer.cpp](src/ghost_text_renderer.cpp) - Full implementation
- [src/editor/ghost_text_renderer.hpp](src/editor/ghost_text_renderer.hpp) - Alternative variant
- [src/agentic_text_edit.h](src/agentic_text_edit.h) - LSP + ghost text integration (line 23, 75, 104-109, 123-124, 134)
- [src/win32app/Win32IDE_GhostText.cpp](src/win32app/Win32IDE_GhostText.cpp) - Win32 backend
- [src/ai_completion_real.cpp](src/ai_completion_real.cpp) - Token streaming (line 76)

**Architecture**:
- Real-time inline predictions using AI completion provider
- Streaming token-by-token for live preview
- Integrated with LSP client for language-aware suggestions

**Status**: Fully wired and operational in GUI layer.

---

### 2. Chat Sidebar (Qt-free)
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/win32app/Win32IDE_ChatPanel.cpp](src/win32app/Win32IDE_ChatPanel.cpp) - Native Win32 chat UI
- [src/win32app/Win32IDE_Sidebar.cpp](src/win32app/Win32IDE_Sidebar.cpp) - Sidebar container
- [src/win32app/Win32IDE_Sidebar_Pure.asm](src/win32app/Win32IDE_Sidebar_Pure.asm) - Pure MASM rendering variant
- [src/win32app/Win32IDE_Sidebar_Pure_Minimal.asm](src/win32app/Win32IDE_Sidebar_Pure_Minimal.asm) - Minimal variant
- [src/chatpanel.cpp](src/chatpanel.cpp) - Legacy base class
- [src/chatpanel.h](src/chatpanel.h) - Interface

**Architecture**:
- Pure Win32 HWND-based, no Qt dependency
- Message rendering with rich text support
- Input handling with send/clear controls
- Model selector for swapping inference backends
- Streaming response display

**Status**: Production-ready, fully integrated with agent execution.

---

### 3. Slash Command Parser
**Status**: ✅ **IMPLEMENTED + WIRED**  
**Primary Files**:
- [src/agentic/slash_command_parser.hpp](src/agentic/slash_command_parser.hpp) - Parser interface + command schema mapping
- [src/agentic/slash_command_parser.cpp](src/agentic/slash_command_parser.cpp) - Tokenizer + command parser implementation
- [src/agentic/AgenticChatSession.cpp](src/agentic/AgenticChatSession.cpp) - Runtime wiring for slash-first tool execution

**Related Components**:
- [src/agentic/AgentToolHandlers.cpp](src/agentic/AgentToolHandlers.cpp) - Tool dispatching backend
- [src/win32app/Win32IDE_Commands.cpp](src/win32app/Win32IDE_Commands.cpp) - Command routing infrastructure
- [src/win32app/Win32IDE_CommandHandlers.cpp](src/win32app/Win32IDE_CommandHandlers.cpp) - Handler registry

**Architecture**:
- Slash command detection via `SlashCommandParser::IsSlashCommand()`
- Structured parse to tool-call JSON via `ParsedCommand::ToToolCall()`
- Direct execution path in `AgenticChatSession::RunTurn()` for `/edit`, `/terminal`, `/search`, `/read`, `/write`, `/refactor`, `/git`, `/help`

**Status**: Live in the native agentic session path.

---

### 4. Multi-File Edit Planning
**Status**: ✅ **IMPLEMENTED (ENGINE) / ⚠️ PARTIAL (UI orchestration polish)**  
**Primary Files**:
- [src/agentic/multi_file_edit_plan.hpp](src/agentic/multi_file_edit_plan.hpp) - Plan model + builder API
- [src/agentic/multi_file_edit_plan.cpp](src/agentic/multi_file_edit_plan.cpp) - Sequencing, execution, rollback
- [src/agentic/AgentToolHandlers.cpp](src/agentic/AgentToolHandlers.cpp) - Propose/apply tool routes for plan execution
- [src/multi_tab_editor.h](src/multi_tab_editor.h) - Tab management (UI only)
- [src/multi_tab_editor.cpp](src/multi_tab_editor.cpp) - Implementation

**Multi-File Diff Support**:
- [src/ui/diff_viewer.hpp](src/ui/diff_viewer.hpp) - Multi-view potential
- [src/ui/diff_preview_widget.h](src/ui/diff_preview_widget.h) - Per-file preview

**Current Gap**:
- Multi-file tab UI fully functional
- Diff preview per-file exists
- Engine-level sequencing, conflict detection, and rollback are implemented
- Remaining gap is richer UI workflow around plan preview/approval orchestration

**TODO**: 
- Add explicit UI-driven plan approval/step visualization for large edit batches
- Add metrics/telemetry for multi-file apply and rollback outcomes

---

### 5. Terminal Execution
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/terminal_pool.h](src/terminal_pool.h) - Terminal session manager
- [src/terminal_pool.cpp](src/terminal_pool.cpp) - Implementation (using ConPTY API)
- [src/win32app/TerminalManager_Win32.cpp](src/win32app/TerminalManager_Win32.cpp) - Win32 integration
- [src/win32app/Win32IDE_TerminalManager_Win32.cpp](src/win32app/Win32IDE_TerminalManager_Win32.cpp) - IDE wiring
- [src/terminal/sandboxed_terminal.cpp](src/terminal/sandboxed_terminal.cpp) - Restricted environment
- [src/terminal/embedded_terminal.cpp](src/terminal/embedded_terminal.cpp) - In-IDE terminal
- [src/agent/dynamic_powershell_terminal_manager.cpp](src/agent/dynamic_powershell_terminal_manager.cpp) - PowerShell orchestrator

**Architecture**:
- Windows ConPTY (PseudoConsole) for terminal emulation
- Multiple concurrent sessions via `TerminalPool`
- Streaming I/O (writeInput, readOutput methods)
- Resize support (PTY dimensions)

**Status**: Live and operational for:
- User terminal tabs
- Background task execution
- Agent-driven command runners
- PowerShell script execution

**TODO**: Enhanced async handling, command timeout guards, better error recovery.

---

### 6. Diff Preview
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/ui/diff_preview_widget.h](src/ui/diff_preview_widget.h) - Widget class
- [src/ui/diff_preview_widget.cpp](src/ui/diff_preview_widget.cpp) - Rendering
- [src/ui/diff_viewer.hpp](src/ui/diff_viewer.hpp) - Viewer component
- [src/ui/diff_dock.h](src/ui/diff_dock.h) - Docking container
- [src/ui/diff_dock.cpp](src/ui/diff_dock.cpp) - Dock UI
- [src/win32app/Win32IDE_DiffView.cpp](src/win32app/Win32IDE_DiffView.cpp) - Win32 integration
- [src/git/semantic_diff_analyzer.hpp](src/git/semantic_diff_analyzer.hpp) - Smart diffing
- [src/git/semantic_diff_analyzer.cpp](src/git/semantic_diff_analyzer.cpp) - Implementation
- [src/core/neurological_diff.hpp](src/core/neurological_diff.hpp) - AI-enhanced diffing
- [src/core/neurological_diff.cpp](src/core/neurological_diff.cpp) - Implementation

**Features**:
- Side-by-side diff view
- Color-coded additions/deletions/modifications
- Semantic analysis (understands code structure)
- Inline hunks display
- AI-enhanced matching (neurological diff)

**Status**: Fully operational for git diffs and code changes.

**TODO**: Performance optimization for 10k+ line diffs, inline commenting UI.

---

### 7. Repository Indexing
**Status**: ⚠️ **PARTIAL (Core + incremental monitor implemented, large-scale optimization pending)**  
**Primary Files**:
- [src/indexing/semantic_index.h](src/indexing/semantic_index.h) - High-level API
- [src/indexing/semantic_index.cpp](src/indexing/semantic_index.cpp) - Implementation
- [src/core/vector_index.h](src/core/vector_index.h) - HNSW embeddings index (comprehensive, 200+ lines)
- [src/core/vector_index.cpp](src/core/vector_index.cpp) - Full HNSW implementation
- [src/core/codebase_indexer.cpp](src/core/codebase_indexer.cpp) - Codebase scanning orchestrator
- [src/core/codebase_index.cpp](src/core/codebase_index.cpp) - Index persistence
- [src/indexing/incremental_indexer.hpp](src/indexing/incremental_indexer.hpp) - Incremental watcher/indexer API
- [src/indexing/incremental_indexer.cpp](src/indexing/incremental_indexer.cpp) - Change detection + batch processing
- [src/context/indexer.cpp](src/context/indexer.cpp) - Context-aware indexer
- [src/tools/git_client.h](src/tools/git_client.h) - Git integration
- [src/git/git_context.h](src/git/git_context.h) - Git metadata
- [src/git/git_wired.hpp](src/git/git_wired.hpp) - Wiring

**Architecture**:
- **CodeChunk struct**: file path, line range, embedding (384/768-dim), content, modification time
- **Chunking strategies**: Function-level, class-level, sliding window, file summary
- **HNSW index**: Approximate nearest neighbor search with LRU cache
- **Change detection**: Epoch millisecond timestamps per chunk

**Status**: Vector indexing fully operational. File discovery and incremental updates need enhancement.

**TODO**: 
- Optimize incremental watcher behavior for very large repositories
- Disk persistence for embeddings (avoid recompute)
- Batch processing for 40GB+ codebases

---

### 8. Vector Search (RAG)
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/core/vector_index.h](src/core/vector_index.h) - Core HNSW with CodeChunk
- [src/core/vector_index.cpp](src/core/vector_index.cpp) - Full implementation
- [src/indexing/semantic_index.h](src/indexing/semantic_index.h) - Public API
- [src/indexing/semantic_index.cpp](src/indexing/semantic_index.cpp) - Wrapper
- [src/core/codebase_indexer.cpp](src/core/codebase_indexer.cpp) - Orchestrator
- [src/asm/monolithic/ast_indexer.asm](src/asm/monolithic/ast_indexer.asm) - MASM variant
- [src/ai/symbol_graph_indexer.cpp](src/ai/symbol_graph_indexer.cpp) - Symbol indexing
- [src/win32app/Win32IDE_SemanticIndex.cpp](src/win32app/Win32IDE_SemanticIndex.cpp) - IDE integration

**Architecture**:
- Semantic search via embeddings (384-dim Phi-3 or 768-dim gte-large)
- HNSW approximate nearest neighbor search
- Chunking and re-ranking for quality results
- LRU cache for performance
- Change detection via timestamps

**Status**: Fully operational RAG pipeline with semantic search and re-ranking.

**TODO**: Performance tuning for large codebases.

---

### 9. Memory Persistence
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/agentic_memory_system.h](src/agentic_memory_system.h) - Modern agentic memory interface
- [src/agentic_memory_system.cpp](src/agentic_memory_system.cpp) - Full implementation
- [src/agent_memory.h](src/agent_memory.h) - Persistent agent memory (line 2)
- [src/agent_memory.cpp](src/agent_memory.cpp) - Implementation with search (line 121-216)
- [src/memory_core.h](src/memory_core.h) - Core memory layer
- [src/memory_core.cpp](src/memory_core.cpp) - Implementation
- [src/memory_space_manager.cpp](src/memory_space_manager.cpp) - Space management
- [src/memory_plugins.cpp](src/memory_plugins.cpp) - Plugin system
- [src/legacy/qtapp/memory_persistence_system.h](src/legacy/qtapp/memory_persistence_system.h) - Legacy Qt variant (quarantined)
- [src/legacy/qtapp/memory_persistence_system.cpp](src/legacy/qtapp/memory_persistence_system.cpp) - Legacy implementation (quarantined)
- [src/win32app/memory_modules/](src/win32app/memory_modules/) - Win32 module templates

**Architecture**:
- Structured memory entries (key-value with metadata)
- Searchable by content (line 116, 121-216)
- JSON-based persistence
- Transaction logging
- Per-agent memory namespaces

**MemoryEntry Structure**:
```cpp
struct MemoryEntry {
    std::string key;
    std::string value;
    std::string type;       // "fact", "code", "conversation", etc
    int64_t timestamp;      // Creation time
    int64_t lastAccessed;   // Usage tracking
    int refCount;           // Usage frequency
};
```

**Status**: Fully operational with search capabilities integrated into agent decision-making.

**TODO**: Encryption for sensitive data, performance optimization for 10k+ entries.

---

### 10. MCP Server Support
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/mcp_server_manager.h](src/mcp_server_manager.h) - Manager interface (comprehensive, 35 lines)
- [src/mcp_server_manager.cpp](src/mcp_server_manager.cpp) - Implementation
- [src/mcp_client.h](src/mcp_client.h) - MCP client protocol
- [src/mcp_client.cpp](src/mcp_client.cpp) - Client implementation
- [src/mcp_integration.cpp](src/mcp_integration.cpp) - Integration layer
- [src/github_mcp_bridge.h](src/github_mcp_bridge.h) - GitHub MCP bridge
- [src/github_mcp_bridge.cpp](src/github_mcp_bridge.cpp) - GitHub implementation
- [src/win32app/mcp_hooks.asm](src/win32app/mcp_hooks.asm) - ASM wiring
- [src/win32app/Win32IDE_MCP.cpp](src/win32app/Win32IDE_MCP.cpp) - Win32 integration
- [src/win32app/Win32IDE_MCPHooks.h](src/win32app/Win32IDE_MCPHooks.h) - Hook declarations
- [src/win32app/Win32IDE_MCPHooks.cpp](src/win32app/Win32IDE_MCPHooks.cpp) - Hook implementation

**Architecture**:
- Singleton `MCPServerManager` for lifecycle management
- Server discovery and registration
- Tool interface bridging to tool registry
- JSON-RPC protocol implementation

**Supported Servers**:
- GitHub MCP (fully implemented)
- Custom server support via config
- Extensible architecture for new servers

**Status**: Live MCP protocol support with GitHub integration. Ready for additional servers.

**TODO**: Implement Slack, Jira, Linear MCP servers.

---

### 11. Tool Registry
**Status**: ✅ **IMPLEMENTED**  
**Primary Files**:
- [src/tool_registry.h](src/tool_registry.h) - C-linkage API (static methods)
- [src/tool_registry.cpp](src/tool_registry.cpp) - Implementation
- [src/tool_registry.hpp](src/tool_registry.hpp) - Modern C++ wrapper (188 lines)
- [src/tool_registry_init.h](src/tool_registry_init.h) - Initialization interface
- [src/tool_registry_init.cpp](src/tool_registry_init.cpp) - Core tool registration
- [src/tool_registry_advanced.cpp](src/tool_registry_advanced.cpp) - Advanced tools
- [src/tool_registry_thermal.cpp](src/tool_registry_thermal.cpp) - Performance/thermal tools
- [src/agentic/ToolRegistry.h](src/agentic/ToolRegistry.h) - Agentic variant
- [src/runtime/SovereignToolRegistry.h](src/runtime/SovereignToolRegistry.h) - Sovereign variant
- [src/UnifiedToolRegistry.h](src/UnifiedToolRegistry.h) - Unified interface
- [src/agentic/AgentToolHandlers.cpp](src/agentic/AgentToolHandlers.cpp) - Tool handlers (line 1030-1031)

**C-API**:
```cpp
void register_tool(const std::string& name, ToolFunc fn);
void inject_tools(AgentRequest& req);
std::string list_tools();
bool execute_tool(const std::string& name, const std::string& params_json, std::string& out_result);
```

**Core Tools** (~23+):
- File: create, read, write, delete, chmod
- Directory: mkdir, readdir, rmdir, ls
- Compilation: compile (g++, clang, MASM, etc)
- Debug: breakpoint, inspect vars, stack trace
- Git: commit, diff, log, status
- Model: train, evaluate, export
- Profiling: cpu, memory, io
- Search: code search, regex find

**Status**: Fully operational with ~23 tools integrated. Extensible for plugins.

**TODO**: Dynamic tool loading from plugins, tool versioning, parameter schema validation.

---

### 12. Custom Instructions
**Status**: ⚠️ **PARTIAL (Provider + runtime prompt integration live, broader IDE-wide adoption pending)**  
**Primary Files**:
- [src/core/instructions_provider.hpp](src/core/instructions_provider.hpp) - Provider interface
- [src/core/scoped_instructions_provider.hpp](src/core/scoped_instructions_provider.hpp) - Cascading scope provider
- [src/core/scoped_instructions_provider.cpp](src/core/scoped_instructions_provider.cpp) - Scope resolution + merge logic
- [src/agentic/AgenticChatSession.cpp](src/agentic/AgenticChatSession.cpp) - Scoped instruction injection into system prompt
- [src/win32app/Win32IDE_Instructions.cpp](src/win32app/Win32IDE_Instructions.cpp) - Win32 UI integration
- Config files: `.agent.md`, `.instructions.md` - Instruction sources

**Architecture**:
- Per-project instructions loaded from workspace root
- Per-directory override support via cascading config
- Instruction scope management (project, directory, file-level)
- Integration with agent decision-making

**Current Status**: Scoped loading and prompt injection are active in agentic chat path; full IDE-wide consumption remains partial.

**TODO**:
- Expand scoped-instruction usage to all command/automation entry paths
- Add stronger validation/safety filtering for malformed instruction files

---

## PART 2: EXISTING MODULE STRUCTURE

### Directory Tree (Condensed)
```
d:\rawrxd\src\
├── agentic/                    # Agent execution layer (20+ subsystems)
│   ├── agentic_*.cpp/h         # Agentic components
│   ├── ToolRegistry.h          # Agent tool registry
│   ├── AgentToolHandlers.cpp   # Tool command dispatch
│   ├── autonomous_*.cpp        # Autonomous subsystems
│   └── [20 more files]
│
├── win32app/                   # Win32IDE main codebase (397 files!)
│   ├── Win32IDE.cpp/h          # Main window & entry
│   ├── Win32IDE_*.cpp          # Feature modules
│   │   ├── ChatPanel, Sidebar, Terminal, Extensions
│   │   ├── Debugger, Git, LSP, Marketplace
│   │   ├── Agent, Refactor, Tasks, Build
│   │   └── [~380 more feature modules]
│   ├── HeadlessIDE.cpp/h       # HTTP server surface
│   ├── Sidebar_*.asm/cpp       # MASM sidebar variants
│   ├── Terminal*.cpp           # Terminal integration
│   ├── mcp_hooks.asm           # ASM MCP wiring
│   └── [deep subsystem files]
│
├── core/                       # Core infrastructure
│   ├── vector_index.h/cpp      # HNSW embeddings index
│   ├── codebase_indexer.cpp    # Repository scanning
│   ├── execution_governor.h    # Execution control
│   ├── agent_infrastructure.h  # Agent interfaces
│   ├── instructions_provider.hpp
│   └── [20+ interfaces]
│
├── inference/                  # Inference engines
│   ├── cpu_inference_engine.cpp
│   ├── dml_inference_engine.cpp
│   ├── vulkan_compute.cpp
│   ├── ultra_fast_inference.cpp
│   └── [GPU backends]
│
├── ggml/                       # llama.cpp integration
│   ├── ggml.c/cpp              # Core GGML
│   ├── gguf_*.cpp              # GGUF format
│   ├── *-backend/              # Compute (cuda, hip, vulkan, metal, etc)
│   └── tests/
│
├── ui/                         # UI components
│   ├── diff_preview_widget.h/cpp
│   ├── diff_dock.h/cpp
│   ├── diff_viewer.hpp
│   └── [UI elements]
│
├── terminal/                   # Terminal subsystem
│   ├── sandboxed_terminal.cpp
│   ├── embedded_terminal.cpp
│   └── [terminal variants]
│
├── indexing/                   # Semantic indexing
│   └── semantic_index.h/cpp
│
├── git/                        # Git integration
│   ├── git_context.h/cpp
│   ├── semantic_diff_analyzer.cpp
│   └── git_wired.hpp
│
├── qtapp/                      # Qt modules (deprecated)
│   ├── memory_persistence_system.h/cpp
│   ├── gitignore_parser.h/cpp
│   └── [Qt-based features being removed]
│
├── agentic_*.cpp/h             # Main agentic interfaces
├── agent_*.cpp/h               # Agent infrastructure
├── tool_registry*.cpp/h        # Tool registry implementations
├── mcp_*.cpp/h                 # MCP integration
├── terminal_pool.h/cpp         # Terminal manager
├── memory_*.cpp/h              # Memory systems
├── ghost_text_renderer.*       # Ghost text rendering
├── chatpanel.cpp/h             # Chat UI
└── [100+ supporting files]
```

### Key Classes & Hierarchy

**Agentic Core**:
- `AgenticIDE` (agentic_ide.h) - Main orchestrator with 10+ subsystems
- `AgenticExecutor` (agentic_executor.h) - Task execution with 20+ capabilities
- `ZeroDayAgenticEngine` - Advanced reasoning
- `AutonomousIntelligenceOrchestrator` - Multi-agent coordination
- `PlanOrchestrator` (plan_orchestrator.h) - Execute decomposed plans

**Tool/Agent Dispatch**:
- `ToolRegistry` (tool_registry.h, tool_registry.hpp) - Dual API (C and C++)
- `AgentToolRegistry` (headers/agent_infrastructure.h)
- `MCPServerManager` (mcp_server_manager.h) - MCP protocol manager
- `GitMCPBridge` - GitHub tool access via MCP

**Search & Indexing**:
- `VectorIndex` (core/vector_index.h) - HNSW ANN with CodeChunk
- `SemanticIndex` (indexing/semantic_index.h) - Wrapper API
- `CodeChunk` struct - Embedding + source mapping

**Terminal & Process**:
- `TerminalPool` (terminal_pool.h) - Session manager
- `SandboxedTerminal` - Restricted execution
- `EmbeddedTerminal` - IDE-integrated terminal
- `Win32TerminalManager` - Platform integration

**Memory & Persistence**:
- `AgenticMemorySystem` (agentic_memory_system.h)
- `AgentMemory` (agent_memory.h) - Search-capable memory
- `MemoryPersistenceSystem` (qtapp/memory_persistence_system.h)

**Text & Editing**:
- `AgenticTextEdit` (agentic_text_edit.h) - LSP + ghost text
- `MultiTabEditor` (multi_tab_editor.h) - Multi-file tabs
- `GhostTextRenderer` - Inline suggestions
- `EditOperation` - Text edit model

**UI & Rendering**:
- `DiffPreviewWidget` (ui/diff_preview_widget.h)
- `DiffDock` (ui/diff_dock.h)
- `SemanticDiffAnalyzer` (git/semantic_diff_analyzer.hpp)
- `WindowManager` (win32app/WindowManager.h)

---

## PART 3: BUILD CONFIGURATION

### CMake (Primary)
**File**: [CMakeLists.txt](CMakeLists.txt) (200+ lines)

**Key Phases**:
1. **SDK Resolution** - Auto-detect Windows SDK and MSVC paths
   - Tries `D:\VS2022Enterprise` then `C:\VS2022Enterprise` or BuildTools
   - Multi-SDK support (10.0.22621.0, 10.0.26100.0) with fallback
   - Injects into `ENV{INCLUDE}`, `ENV{LIB}`, `ENV{PATH}`

2. **Compiler Setup**:
   - `CMAKE_C_COMPILER` → cl.exe
   - `CMAKE_CXX_COMPILER` → cl.exe
   - `CMAKE_LINKER` → link.exe
   - `CMAKE_ASM_MASM_COMPILER` → ml64.exe (MASM64)
   - `CMAKE_RC_COMPILER` → rc.exe (Resource Compiler)
   - `CMAKE_MT` → mt.exe (Manifest Tool)

3. **Library Paths** - Aggregates from MSVC and SDK
   - `${_MSVC_ROOT}/lib/x64`
   - `${_MSVC_ROOT}/lib/onecore/x64`
   - `${_WIN10_SDK_ROOT}/Lib/.../ucrt/x64`
   - `${_WIN10_SDK_ROOT}/Lib/.../um/x64`

4. **Scaffold Enforcement** - `enforce_no_scaffold` target validates codebase (prevents testing stubs in production)

### Toolchain (Phases)
Located: `toolchain/from_scratch/`
- **Phase 1**: Assembler setup
- **Phase 2**: Linker configuration
- **Phase 3**: Imports resolution
- **Phase 4**: Resource compilation

Each phase has its own `CMakeLists.txt` with tests.

### Build Generators
Supported:
- **Ninja** (preferred, fastest)
- **Visual Studio** (2022)
- **NMake** (legacy)

### Targets
- **RawrXD-Win32IDE** - Main GUI application
- **RawrXD_Headless** - HTTP server binary
- **RawrXD_Native_Core.dll** - Native inference bridge
- **RawrXD_Inference_Core** - Inference engines
- **GGML** - llama.cpp dependency
- **Vulkan/HIP/DML** - GPU backend targets

### Compilation Constraints
- **MASM**: Pure x64 assembly (no scaffolding, per user preference)
- **C++**: Modern C++ with /W4 warnings
- **No Qt in new code paths** - Only in deprecated `qtapp/`
- **Link to Windows SDK** - Native API calls

---

## PART 4: CURRENT ARCHITECTURE

### 4.1 GUI: Win32IDE (Primary)

**Entry Point**: [src/win32app/Win32IDE_Main.cpp](src/win32app/Win32IDE_Main.cpp)

**Layer 1 — Native Windows**:
- Main window: [src/win32app/Win32IDE.cpp](src/win32app/Win32IDE.cpp) (WndProc)
- WebView2 bridge: [src/win32app/Win32IDE_WebView2.cpp](src/win32app/Win32IDE_WebView2.cpp) (Monaco editor)
- Window management: [src/win32app/WindowManager.h/cpp](src/win32app/WindowManager.h)

**Layer 2 — Feature Modules** (397 total):

| Category | Modules | Files |
|----------|---------|-------|
| **Chat & Input** | Chat panel, input handling, message rendering | ChatPanel.cpp, ChatEvents.cpp, ChatMessageRenderer.cpp |
| **Sidebar** | File explorer, outline, search | Sidebar.cpp, SidebarPanels.cpp, Sidebar_Pure*.asm |
| **Terminal** | Terminal management, tab split, profiles | TerminalManager*.cpp, TerminalSplit.cpp, TerminalProfiles.cpp |
| **Editor** | Multi-tab editor, syntax highlighting, editing | EditorEngine.cpp, SyntaxHighlight.cpp, MultiCursor.cpp |
| **Extensions** | Extension marketplace, installer, management | ExtensionsPanel.cpp, ExtensionMarketplace.cpp, VSIXInstaller.hpp |
| **LSP** | Language server integration, diagnostics | LSPClient.cpp, LSP_AI_Bridge.cpp, InlayHints.cpp |
| **Git** | Git panel, diff view, status | Git.cpp, GitPanel.cpp, DiffView.cpp |
| **Debugger** | Debug panel, breakpoints, variables | Debugger.cpp, NativeDebugPanel.cpp, CallStackSymbols.cpp |
| **Agent** | Agent integration, command handling | AgenticBridge.cpp, AgentPanel.cpp, AgentCommands.cpp |
| **Build** | Build runner, compilation output | Build.cpp, BuildRunner.cpp, CompilerPanel.cpp |
| **Others** | Settings, themes, tasks, tools, telemetry, etc | Settings.cpp, Themes.cpp, Tasks.cpp, Telemetry.cpp, [100+] |

**Layer 3 — Agent Integration**:
- [src/win32app/Win32IDE_AgenticBridge.cpp](src/win32app/Win32IDE_AgenticBridge.cpp) - Bridge to agent
- [src/win32app/Win32IDE_AgentPanel.cpp](src/win32app/Win32IDE_AgentPanel.cpp) - Agent UI
- [src/win32app/Win32IDE_AgentCommands.cpp](src/win32app/Win32IDE_AgentCommands.cpp) - Command dispatch
- [src/win32app/Win32IDE_AutonomousAgent.cpp](src/win32app/Win32IDE_AutonomousAgent.cpp) - Autonomous executor

**Layer 4 — Backend Inference**:
- [src/win32app/Win32IDE_AIBackend.cpp](src/win32app/Win32IDE_AIBackend.cpp) - Model selection
- [src/win32app/Win32IDE_LocalServer.cpp](src/win32app/Win32IDE_LocalServer.cpp) - HTTP completions server
- [src/win32app/Win32IDE_ModelLoaderBridge.cpp](src/win32app/Win32IDE_ModelLoaderBridge.cpp) - Model loading
- Inference routing to CPU/GPU backends

### 4.2 Headless: HTTP Server Mode

**Entry Point**: [src/win32app/HeadlessIDE.cpp](src/win32app/HeadlessIDE.cpp) (when called with --headless flag)

**Architecture**:
- No GUI, no HWND, no message loop
- WinHttp server listening on configurable port (default: 8000)
- Integrated all backend systems (inference, tools, memory)
- JSON request/response only

**Modes** (switch via CLI args or env var):
1. **Server** - Long-running HTTP listener
   - `/health` - Status check
   - `/v1/models` - Available models
   - `/v1/completions` - Text completion
   - `/v1/chat/completions` - Chat completion
   - Agent routes for tool execution

2. **REPL** - Interactive shell
   - Read user prompt from stdin
   - Process via inference engine
   - Stream output to stdout

3. **SingleShot** - Process one request
   - Read input from arg or stdin
   - Generate response
   - Print result
   - Exit

4. **Batch** - Process file list
   - Read prompts from file
   - Generate all responses
   - Output to results file

**Constants** (size guards):
- Max prompt: 32 KB
- Max batch input: 4 MB
- Max batch prompts: 10,000
- Max HTTP request: 64 KB
- Max HTTP response: 1 MB

### 4.3 Agent Dispatch Flow

```
User Input (Chat or Command)
        ↓
    ChatInterface / AgentToolHandlers
        ↓
    AgenticBridge (Win32IDE layer)
        ↓
    AgenticExecutor or ZeroDayAgenticEngine
        ↓
    Plan Orchestrator (decompose into steps)
        ↓
    For each step:
        ├─ Route to Tool Registry?
        │  ├─ Local tool execution
        │  └─ Return result JSON
        ├─ Route to Model?
        │  ├─ Call inference (CPU/GPU)
        │  └─ Stream response
        └─ Route to MCP?
           ├─ Call MCPServerManager
           └─ Execute via server
        ↓
    Memory System (store interaction)
        ↓
    Render response in UI / return via HTTP
```

**Tool Execution Path**:
1. User requests tool (e.g., "compile my project")
2. Command parsed by `AgentToolHandlers` or slash command parser
3. `ToolRegistry::execute_tool("compile", json_params)` called
4. Tool function executes (real compilation, file I/O, etc)
5. Result serialized to JSON
6. Agent processes result (success/failure)
7. Generate follow-up response
8. Store in memory for context

**MCP Path** (alternative):
1. User requests external tool (e.g., GitHub operation)
2. `MCPServerManager::call_tool("github_server", "create_issue", args)`
3. MCP client routes to server
4. Server executes tool
5. Result returned through manager
6. Integrated into response

---

## PART 5: TOOL REGISTRY & MCP FRAMEWORK

### Tool Registry Architecture

**Dual API**:
```cpp
// C-style API (static methods)
void ToolRegistry::register_tool(const std::string& name, ToolFunc fn);
bool ToolRegistry::execute_tool(const std::string& name, const std::string& params_json, std::string& out_result);

// C++ wrapper
class ToolRegistry {
    void registerTool(const std::string& name, ToolFunc fn);
    bool executeTool(const std::string& name, const json& params, json& result);
};
```

**Tool Function Signature**:
```cpp
using ToolFunc = std::function<std::string(const std::string&)>;
// Input: JSON string of parameters
// Output: JSON string of result
```

**Tool Registration** ([src/tool_registry_init.cpp](src/tool_registry_init.cpp)):
```cpp
ToolRegistry::ensure_core_tools();  // On startup, registers:
  - file_create(path, content)
  - file_read(path)
  - file_write(path, content)
  - file_delete(path)
  - directory_create(path)
  - directory_list(path)
  - compile(project_path, compiler)
  - run_executable(path, args)
  - train_model(dataset, model_config)
  - debug_breakpoint(file, line)
  - [and more...]
```

**Advanced Tools** ([src/tool_registry_advanced.cpp](src/tool_registry_advanced.cpp)):
- Code analysis
- Refactoring operations
- Performance profiling
- Security scanning

**Thermal Tools** ([src/tool_registry_thermal.cpp](src/tool_registry_thermal.cpp)):
- CPU/memory monitoring
- Resource tracking
- Performance metrics

### MCP Integration

**Manager** ([src/mcp_server_manager.h](src/mcp_server_manager.h)):
```cpp
class MCPServerManager {
    static MCPServerManager& instance();
    void initialize();
    std::vector<std::string> get_available_servers() const;
    std::vector<Tool> get_server_tools(const std::string& server_name) const;
    nlohmann::json call_tool(const std::string& server_name,
                            const std::string& tool_name,
                            const nlohmann::json& arguments);
};
```

**Client** ([src/mcp_client.h](src/mcp_client.h)):
- JSON-RPC protocol implementation
- Server communication
- Result parsing

**Bridge** ([src/github_mcp_bridge.h](src/github_mcp_bridge.h)):
- GitHub-specific MCP integration
- Issue/PR operations
- Repository access

**Wiring**:
- [src/win32app/Win32IDE_MCP.cpp](src/win32app/Win32IDE_MCP.cpp) - IDE integration
- [src/win32app/mcp_hooks.asm](src/win32app/mcp_hooks.asm) - ASM entry points
- [src/mcp_integration.cpp](src/mcp_integration.cpp) - Initialization

---

## PART 6: FEATURE COMPLETION MATRIX

| Feature | Status | Primary File | Implementation Level | Notes |
|---------|--------|--------------|---------------------|-------|
| Ghost Text | ✅ Live | ghost_text_renderer.cpp | Full | Streaming predictions, LSP-aware |
| Chat Sidebar | ✅ Live | Win32IDE_ChatPanel.cpp | Full | Native Win32, no Qt |
| Slash Commands | ✅ Live | agentic/slash_command_parser.cpp | Full | Parsed + executed via AgenticChatSession |
| Multi-File Edit | ⚠️ Partial | agentic/multi_file_edit_plan.cpp | 75% | Sequencing/rollback done; richer UI orchestration pending |
| Terminal Exec | ✅ Live | terminal_pool.cpp | Full | ConPTY-based |
| Diff Preview | ✅ Live | ui/diff_preview_widget.cpp | Full | With semantic analysis |
| Repo Index | ⚠️ Live | indexing/incremental_indexer.cpp | 75% | HNSW + incremental monitor; scale tuning pending |
| Vector Search | ✅ Live | indexing/semantic_index.cpp | Full | RAG with re-ranking |
| Memory Persist | ✅ Live | agentic_memory_system.cpp | Full | Searchable memory |
| MCP Servers | ✅ Live | mcp_server_manager.cpp | Full | GitHub ready, extensible |
| Tool Registry | ✅ Live | tool_registry.cpp | Full | ~23 tools, plugin-ready |
| Custom Instr | ⚠️ Partial | core/scoped_instructions_provider.cpp | 65% | Scoped loading + chat integration; not universal yet |
| Extensions | ✅ Live | Win32IDE_ExtensionsPanel.cpp | Full | VSIX support |
| LSP | ✅ Live | Win32IDE_LSPClient.cpp | Full | Diagnostics, completions |
| Debugger | ✅ Live | Win32IDE_Debugger.cpp | Full | Native breakpoints |

---

## PART 7: RECOMMENDATIONS

### Immediate (High-value, Low-complexity)

1. **Slash Command Parser** (NEW)
   - Completed in `src/agentic/slash_command_parser.hpp/.cpp`
   - Runtime wiring completed in `src/agentic/AgenticChatSession.cpp`
   - Next: add parser-aware telemetry and command analytics

2. **Custom Instructions Full** (EXTEND)
   - Scope provider implemented in [src/core/scoped_instructions_provider.hpp](src/core/scoped_instructions_provider.hpp)
   - Integration active in [src/agentic/AgenticChatSession.cpp](src/agentic/AgenticChatSession.cpp)
   - Next: propagate into all orchestration/CLI paths + harden validation

3. **MCP: Slack Server** (ADD)
   - Create: `src/mcp/slack_mcp_bridge.h/cpp`
   - Webhook integration, message sending
   - Configuration: Slack token management
   - ~100 lines of code

### Short-term (1-2 weeks)

1. **Multi-File Edit Sequencing** (ENHANCE)
   - Core `MultiFileEditPlan` engine is implemented in `src/agentic/multi_file_edit_plan.*`
   - Next: route more UI/refactor entry points through the plan engine
   - Add richer preview, approval, and rollback visualization in Win32IDE

2. **Repository Indexing Incremental** (ENHANCE)
   - Incremental indexer exists in `src/indexing/incremental_indexer.*`
   - Next: harden watcher behavior for large repositories
   - Add: disk persistence for embeddings and restart recovery

3. **Tool Plugin System** (ADD)
   - Create: Plugin loader, manifest format
   - Support: External .dll tools
   - Integration: Dynamic registration
   - ~250 lines of code

### Long-term (1-2 months)

1. **Additional MCP Servers** (ADD)
   - Jira, Linear, Trello, etc
   - Standard implementation per server
   - ~100 lines per server

2. **Encrypted Memory** (ENHANCE)
   - Add: DPAPI encryption for storage
   - Performance: Cache decrypted entries
   - ~150 lines of code

3. **Advanced Slash Commands** (ENHANCE)
   - Grammar: `/edit --dry-run`, `/search --regex`, etc
   - Chaining: `/edit file1 && /test`
   - ~400 lines of code

---

## SUMMARY

RawrXD is a sophisticated multi-layered IDE with comprehensive feature coverage. The codebase features:

✅ **Implemented & Live**:
- Full agentic execution framework
- ~397 Win32IDE feature modules
- Multiple inference backends (CPU, GPU, HIP, Vulkan, DML)
- Semantic search with HNSW embeddings
- Memory persistence with search
- MCP protocol support
- ~23 built-in tools
- LSP integration
- Full debugger support
- Extensions & marketplace

⚠️ **Partial Implementation**:
- Multi-file edit planning engine exists; broader UI orchestration remains
- Repository indexing includes incremental monitoring; scale and persistence remain
- Custom instructions are scoped and injected in agent chat; wider adoption remains

❌ **Not Implemented**:
- No major missing item in this four-gap set; remaining work is adoption depth and polish

**Key Files to Focus On**:
1. Win32IDE subsystem: `src/win32app/Win32IDE_*.cpp` (397 files)
2. Agent orchestration: `src/agentic_*.cpp/h`
3. Inference engines: `src/inference/*.cpp`
4. Tool registry: `src/tool_registry*.cpp/h`
5. GGML integration: `src/ggml/*`

**Build System**: Native CMake + MSVC with MASM64, no Qt dependencies in new code.
