# RAWRXD_IDE_PARITY_AUDIT_001
## Full IDE Audit — End-to-End Parity vs VS Code + Copilot / Cursor / Top AI IDEs

Authority: RAWRXD_IDE_PARITY_AUDIT_001
Branch: model-correctness
Commit: a06738794d
Date: 2026-10-01

---

## Scope

This audit covers the complete RawrXD Win32 IDE surface against the
feature set expected of a top-tier AI-native IDE (VS Code + Copilot,
Cursor, Windsurf, Zed, JetBrains AI, Codeium, Tabnine, Continue, etc.).

Every item is classified as one of:
- PRESENT — implemented and wired
- PARTIAL — skeleton/stub exists, not fully wired or certified
- MISSING — not present in source tree
- NOT_APPLICABLE — intentionally out of scope for native Win32 target

---

## Section 1: Core Editor Surface

| Feature | Status | Source | Notes |
|---|---|---|---|
| Text editing (insert/delete/backspace) | PRESENT | Win32IDE_EditorEngine.cpp | Full char/line ops |
| Cursor movement (arrow/home/end/pgup/pgdn) | PRESENT | Win32IDE_EditorEngine.cpp | All VK_ keys handled |
| Mouse click to position cursor | PRESENT | Win32IDE_EditorEngine.cpp | WM_LBUTTONDOWN hit test |
| Mouse wheel scroll | PRESENT | Win32IDE_EditorEngine.cpp | WM_MOUSEWHEEL |
| Selection (keyboard) | PARTIAL | Win32IDE_EditorEngine.cpp | selStart/End stored; shift-select not wired to VK_ handlers |
| Selection (mouse drag) | MISSING | Win32IDE_EditorEngine.cpp | WM_MOUSEMOVE not handled |
| Select All (Ctrl+A) | PRESENT | Win32IDE_EditorEngine.cpp | EditorEngine_SelectAll() |
| Copy / Cut / Paste (Ctrl+C/X/V) | MISSING | Win32IDE_EditorEngine.cpp | No clipboard integration |
| Undo / Redo | MISSING | Win32IDE_EditorEngine.cpp | No undo stack |
| Find (Ctrl+F) | PRESENT | Win32IDE_EditorEngine.cpp | EditorEngine_Find() |
| Replace (Ctrl+H) | PRESENT | Win32IDE_EditorEngine.cpp | EditorEngine_Replace/ReplaceAll() |
| Find in Files | PRESENT | Win32IDE_SearchPanel.cpp | Regex + case-sensitive, 2000 result cap |
| Line numbers | PRESENT | Win32IDE_EditorEngine.cpp | Gutter rendered |
| Syntax highlighting (C/C++) | PRESENT | Win32IDE_EditorEngine.cpp + Win32IDE_SyntaxHighlight.cpp | Keywords, strings, comments, preprocessor, numbers, types |
| Multi-language syntax highlight | MISSING | — | Only C/C++ tokenizer present |
| Bracket matching | MISSING | — | Not implemented |
| Auto-indent | MISSING | — | Not implemented |
| Auto-close brackets/quotes | MISSING | — | Not implemented |
| Code folding | MISSING | — | Not implemented |
| Minimap | MISSING | Win32IDE_Minimap.cpp listed in missing-225 | Source file absent |
| Breadcrumbs | MISSING | Win32IDE_Breadcrumbs.cpp listed in missing-225 | Source file absent |
| Multi-cursor | MISSING | Win32IDE_MultiCursor.cpp listed in missing-225 | Source file absent |
| Column selection | MISSING | — | Not implemented |
| Word wrap | MISSING | — | Not implemented |
| Zoom in/out | MISSING | — | Not implemented |
| Diff view | MISSING | Win32IDE_DiffView.cpp listed in missing-225 | Source file absent |
| Double-buffer paint (no flicker) | PRESENT | Win32IDE_EditorEngine.cpp | CreateCompatibleDC/BitBlt |
| File open | PRESENT | Win32IDE_EditorEngine.cpp | EditorEngine_OpenFile() |
| File save | PRESENT | Win32IDE_EditorEngine.cpp | EditorEngine_SaveFile() |
| Modified indicator (*) | PRESENT | Win32IDE_TabManager.cpp | Tab shows " *" |
| Tab bar | PRESENT | Win32IDE_TabManager.cpp | Open/close/switch tabs |
| Tab scroll (horizontal) | PRESENT | Win32IDE_TabManager.cpp | scrollOffset + WM_MOUSEWHEEL |


---

## Section 2: File Explorer / Sidebar

| Feature | Status | Source | Notes |
|---|---|---|---|
| File tree (TreeView) | PRESENT | Win32IDE_Sidebar.cpp | WC_TREEVIEW with lazy expand |
| Directory enumeration | PRESENT | Win32IDE_Sidebar.cpp | std::filesystem::directory_iterator |
| Dirs-first sort | PRESENT | Win32IDE_Sidebar.cpp | _wcsicmp sort |
| Lazy expand on click | PRESENT | Win32IDE_Sidebar.cpp | TVN_ITEMEXPANDING subclass |
| File icons | PARTIAL | Win32IDE_Sidebar.cpp | LoadIcon(IDI_APPLICATION) placeholder — no real file-type icons |
| Activity bar (Files/Search/SCM/Debug/Exts) | PARTIAL | Win32IDE_Sidebar.cpp | Buttons rendered; only Explorer and Search panels wired |
| Context menu (new file/folder/rename/delete) | MISSING | Win32IDE_Sidebar.cpp | No WM_CONTEXTMENU handler |
| Drag-and-drop reorder | MISSING | — | Not implemented |
| File rename inline | MISSING | — | Not implemented |
| File delete | MISSING | — | Not implemented |
| New file / new folder | MISSING | — | Not implemented |
| Workspace root from open folder | PARTIAL | Win32IDE_Sidebar.cpp | Uses GetCurrentDirectoryW; no "Open Folder" dialog |
| Search results list | PRESENT | Win32IDE_Sidebar.cpp | LISTBOX wired to search panel |
| SCM panel | PRESENT | Win32IDE_GitPanel.cpp | Separate panel, not wired to activity bar SCM button |
| Debug panel | MISSING | Win32IDE_Debugger.cpp listed in missing-225 | Source file absent |
| Extensions panel | MISSING | Win32IDE_MarketplacePanel.cpp listed in missing-225 | Source file absent |

---

## Section 3: Layout Engine

| Feature | Status | Source | Notes |
|---|---|---|---|
| Sidebar + Editor + Chat 3-column layout | PRESENT | Win32IDE_Core.cpp | IDECore_Layout() |
| Bottom panel (Terminal/Git) | PRESENT | Win32IDE_Core.cpp | Split bottom row |
| Resizable panels (drag splitter) | MISSING | — | Fixed pixel widths only |
| Panel show/hide toggle | PRESENT | Win32IDE_Core.cpp | IDECore_ShowPanel() |
| Status bar | PRESENT | Win32IDE_StatusBar.cpp | Token count, streaming state |
| Tab bar above editor | PRESENT | Win32IDE_TabManager.cpp | 28px height |
| DPI awareness | MISSING | — | No DPI scaling logic |
| Window resize reflow | PRESENT | Win32IDE_Core.cpp | WM_SIZE → IDECore_Layout() |


---

## Section 4: AI Chat Panel

| Feature | Status | Source | Notes |
|---|---|---|---|
| Chat message list (user + assistant bubbles) | PRESENT | Win32IDE_ChatPanel.cpp | Bubble layout with role labels |
| Streaming token append | PRESENT | Win32IDE_ChatPanel.cpp | ChatPanel_AppendStreamToken() |
| Streaming indicator ("...") | PRESENT | Win32IDE_ChatPanel.cpp | streaming flag renders dots |
| Scroll to bottom on new message | PRESENT | Win32IDE_ChatPanel.cpp | scrollOffset=999999 |
| Mouse wheel scroll | PRESENT | Win32IDE_ChatPanel.cpp | WM_MOUSEWHEEL |
| Send button | PRESENT | Win32IDE_ChatPanel.cpp | IDC_CHAT_SEND |
| Multi-line input box | PRESENT | Win32IDE_ChatPanel.cpp | ES_MULTILINE EDIT |
| Send on Enter | MISSING | Win32IDE_ChatPanel.cpp | No VK_RETURN subclass on input |
| Cancel streaming | PRESENT | Win32IDE_StreamingUX.cpp | StreamingUX_Cancel() |
| Token count in status bar | PRESENT | Win32IDE_StreamingUX.cpp | Updates every 10 tokens |
| Tool result injection | PRESENT | Win32IDE_AgenticBridge.cpp | AgenticBridge_InjectToolResult() |
| Message history persistence | MISSING | — | In-memory only, lost on restart |
| Conversation context window management | MISSING | — | No context truncation logic |
| System prompt configuration | MISSING | — | Not exposed in UI |
| Model selector in chat | MISSING | — | No per-chat model picker |
| Attach file to chat | MISSING | — | Not implemented |
| Code block rendering in chat | MISSING | Win32IDE_ChatMessageRenderer.cpp listed in missing-225 | Source file absent |
| Markdown rendering in chat | MISSING | — | Plain text only |
| Copy response button | MISSING | — | Not implemented |
| Regenerate response | MISSING | — | Not implemented |
| Edit previous message | MISSING | — | Not implemented |
| Chat history panel | MISSING | Win32IDE_AgentHistory.cpp listed in missing-225 | Source file absent |

---

## Section 5: Inline AI Completions (Ghost Text / Copilot-style)

| Feature | Status | Source | Notes |
|---|---|---|---|
| Ghost text overlay at cursor | PRESENT | Win32IDE_GhostText.cpp | GhostText_Paint() renders grey text |
| 300ms debounce before request | PRESENT | Win32IDE_GhostText.cpp | sleep_for(300ms) in detached thread |
| Accept with Tab | PARTIAL | Win32IDE_GhostText.cpp | GhostText_Accept() exists; Tab key not wired in EditorWndProc |
| Dismiss with Escape | PARTIAL | Win32IDE_GhostText.cpp | GhostText_Dismiss() exists; Escape not wired |
| Heuristic completions (no model) | PRESENT | Win32IDE_GhostText.cpp | for/if/std:: patterns |
| Model-backed completions | PARTIAL | Win32IDE_GhostText.cpp | completionProvider callback slot exists; not wired to Deep2 |
| LSP-backed completions | PRESENT | Win32IDE_LSP_AI_Bridge.cpp | EditorEngine_SetGhostText() called from LSP bridge |
| Multi-line completions | MISSING | — | Single-line suggestion only |
| Completion cycling (next/prev) | MISSING | — | Not implemented |
| Completion confidence score | MISSING | — | Not implemented |


---

## Section 6: LSP Integration

| Feature | Status | Source | Notes |
|---|---|---|---|
| LSP client (stdio JSON-RPC) | PRESENT | Win32IDE_LSPClient.cpp | Full Content-Length framing |
| LSP server launch (external) | PRESENT | Win32IDE_LSPClient.cpp | CreateProcess with pipes |
| textDocument/didOpen | PRESENT | Win32IDE_LSPClient.cpp | LSPClient_DidOpen() |
| textDocument/didChange | PRESENT | Win32IDE_LSPClient.cpp | LSPClient_DidChange() |
| textDocument/completion | PRESENT | Win32IDE_LSPClient.cpp | LSPClient_RequestCompletion() |
| textDocument/hover | PRESENT | Win32IDE_LSPClient.cpp | LSPClient_RequestHover() |
| publishDiagnostics (errors/warnings) | PRESENT | Win32IDE_LSPClient.cpp | Parsed in reader thread |
| Diagnostics squiggles in editor | MISSING | — | Diagnostics parsed but not rendered in editor |
| Hover tooltip popup | MISSING | Win32IDE_HoverTooltips.cpp listed in missing-225 | Source file absent |
| Go to definition | MISSING | — | Not implemented |
| Go to references | MISSING | — | Not implemented |
| Rename symbol | MISSING | Win32IDE_RenamePreview.cpp listed in missing-225 | Source file absent |
| Code actions / quick fix | MISSING | — | Not implemented |
| Signature help | MISSING | — | Not implemented |
| Built-in LSP server (C/C++ keywords) | PRESENT | Win32IDE_LSPServer.cpp | 50-item keyword/type/function completions |
| Completion dropdown UI | MISSING | — | Completions parsed but no popup widget |
| Inlay hints | MISSING | Win32IDE_InlayHints.cpp listed in missing-225 | Source file absent |
| Code lens | MISSING | Win32IDE_CodeLens.cpp listed in missing-225 | Source file absent |
| Outline panel (symbols) | MISSING | Win32IDE_OutlinePanel.cpp listed in missing-225 | Source file absent |
| Problems panel | MISSING | Win32IDE_ProblemsPanel.cpp listed in missing-225 | Source file absent |

---

## Section 7: Terminal

| Feature | Status | Source | Notes |
|---|---|---|---|
| Embedded terminal panel | PRESENT | Win32IDE_TerminalSplit.cpp | cmd.exe /K via CreateProcess |
| Child process stdout reader thread | PRESENT | Win32IDE_TerminalSplit.cpp | TermReaderThread |
| Command input box | PRESENT | Win32IDE_TerminalSplit.cpp | EDIT control at bottom |
| Send command to child stdin | PRESENT | Win32IDE_TerminalSplit.cpp | TerminalSplit_SendCommand() |
| Scrollback buffer (4000 lines) | PRESENT | Win32IDE_TerminalSplit.cpp | deque<string> with pop_front |
| Mouse wheel scroll | PRESENT | Win32IDE_TerminalSplit.cpp | WM_MOUSEWHEEL |
| ANSI escape code rendering | MISSING | — | Raw text only; no color/cursor sequences |
| ConPTY (full VT terminal) | MISSING | — | Pipe-based only; no pseudoconsole |
| Multiple terminal instances | MISSING | — | Single global g_term state |
| Terminal split (horizontal/vertical) | MISSING | — | Not implemented |
| Terminal profile selector (PowerShell/bash/cmd) | MISSING | — | Hardcoded cmd.exe |
| Enter key sends command | MISSING | Win32IDE_TerminalSplit.cpp | WM_COMMAND EN_UPDATE noted but not wired |
| Output callback for agent | PRESENT | Win32IDE_TerminalSplit.cpp | TerminalSplit_SetOutputCallback() |
| GetLastLines for agent observation | PRESENT | Win32IDE_TerminalSplit.cpp | TerminalSplit_GetLastLines() |

---

## Section 8: Git Panel

| Feature | Status | Source | Notes |
|---|---|---|---|
| git status --porcelain parsing | PRESENT | Win32IDE_GitPanel.cpp | GitPanel_Refresh() |
| File list with M/A/D status colors | PRESENT | Win32IDE_GitPanel.cpp | RGB per status char |
| Stage all + commit | PRESENT | Win32IDE_GitPanel.cpp | RunGit("add -A") + RunGit("commit -m") |
| Commit message input | PRESENT | Win32IDE_GitPanel.cpp | ES_MULTILINE EDIT |
| Refresh button | PRESENT | Win32IDE_GitPanel.cpp | IDC_GIT_REFRESH |
| Branch name in header | PRESENT | Win32IDE_GitPanel.cpp | RunGit("rev-parse --abbrev-ref HEAD") |
| Diff view for selected file | PARTIAL | Win32IDE_GitPanel.cpp | GitPanel_GetDiff() returns string; not rendered in UI |
| Log view | PARTIAL | Win32IDE_GitPanel.cpp | GitPanel_GetLog() returns string; not rendered in UI |
| Stage individual file | MISSING | — | Only "add -A" (stage all) |
| Unstage file | MISSING | — | Not implemented |
| Discard changes | MISSING | — | Not implemented |
| Push / Pull | MISSING | — | Not implemented |
| Branch create/switch | MISSING | — | Not implemented |
| Merge / rebase | MISSING | — | Not implemented |
| Inline diff gutter (editor) | MISSING | — | Not implemented |
| Commit history graph | MISSING | — | Not implemented |


---

## Section 9: Agentic Engine / Tool Authority

| Feature | Status | Source | Notes |
|---|---|---|---|
| AgenticBridge (prompt → background thread) | PRESENT | Win32IDE_AgenticBridge.cpp | Detached thread, WM_AGENT_DONE notify |
| StreamingUX (token → ChatPanel) | PRESENT | Win32IDE_StreamingUX.cpp | Full pipeline wired |
| Cancel in-flight generation | PRESENT | Win32IDE_StreamingUX.cpp | StreamingUX_Cancel() |
| Tool result injection to chat | PRESENT | Win32IDE_AgenticBridge.cpp | AgenticBridge_InjectToolResult() |
| Real Deep2 model invocation | PARTIAL | Win32IDE_AgenticBridge.cpp | Echo path only; ide_agentic_gate.cpp not called |
| MODEL → TOOL → OBSERVATION → MODEL loop | MISSING | — | Not certified; D1/D3 lifecycle open |
| Plan mode (read-only) | MISSING | Win32IDE_AgenticPlanningPanel.cpp listed in missing-225 | Source file absent |
| Code mode (edit + build + test) | MISSING | — | Not certified end-to-end |
| Debug mode | MISSING | Win32IDE_AutonomousDebugger.cpp listed in missing-225 | Source file absent |
| Ask mode | MISSING | — | Not certified as read-only |
| Multi-step task decomposition | MISSING | — | Not certified |
| Repository research (enumerate + search) | PARTIAL | Win32IDE_SearchPanel.cpp | Search exists; not wired to agent loop |
| Source modification via agent | PARTIAL | AgentHotPatcher.* exists in src/ | Not wired to IDE agent path |
| Build execution via agent | PARTIAL | Win32IDE_BuildRunner.cpp exists | Not wired to agent loop |
| Test execution via agent | MISSING | — | Not certified |
| Error observation + repair loop | MISSING | — | Not certified |
| Writer authority (single-writer lease) | PRESENT | SingleWriterAuthority.cpp | Lease file mechanism |
| Tool Authority registry | PARTIAL | src/authority/ exists | Not fully wired to IDE agent path |

---

## Section 10: MCP (Model Context Protocol)

| Feature | Status | Source | Notes |
|---|---|---|---|
| MCP client (stdio JSON-RPC) | PRESENT | Win32IDE_MCP.cpp | Full Content-Length framing |
| MCP server launch | PRESENT | Win32IDE_MCP.cpp | CreateProcess with pipes |
| initialize handshake | PRESENT | Win32IDE_MCP.cpp | Protocol version 2024-11-05 |
| tools/list | PRESENT | Win32IDE_MCP.cpp | MCP_ListTools() |
| tools/call | PRESENT | Win32IDE_MCP.cpp | MCP_CallTool() with callback |
| Tool result callback | PRESENT | Win32IDE_MCP.cpp | pendingCallbacks map |
| MCP hooks in IDE commands | PARTIAL | Win32IDE_MCPHooks.cpp | Exists; wiring to agent loop not certified |
| Multiple MCP servers | MISSING | — | Single g_mcp state |
| MCP server configuration UI | MISSING | — | Not implemented |
| resources/list | MISSING | — | Not implemented |
| prompts/list | MISSING | — | Not implemented |
| Sampling (model-side MCP) | MISSING | — | Not implemented |

---

## Section 11: Build / Run Integration

| Feature | Status | Source | Notes |
|---|---|---|---|
| Build runner (launch cmake/msbuild) | PRESENT | Win32IDE_BuildRunner.cpp | Exists in source |
| Build output to terminal panel | PARTIAL | TerminalSplit_AppendOutput() exists | Not confirmed wired to BuildRunner |
| Error parsing from build output | MISSING | — | No compiler error parser |
| Jump to error in editor | MISSING | — | Not implemented |
| Run configuration | MISSING | — | Not implemented |
| Debug launch | MISSING | Win32IDE_Debugger.cpp listed in missing-225 | Source file absent |
| Task runner (tasks.json equivalent) | MISSING | Win32IDE_Tasks.cpp listed in missing-225 | Source file absent |

---

## Section 12: Search

| Feature | Status | Source | Notes |
|---|---|---|---|
| Cross-file text search | PRESENT | Win32IDE_SearchPanel.cpp | Recursive filesystem walk |
| Case-sensitive toggle | PRESENT | Win32IDE_SearchPanel.cpp | Checkbox |
| Regex toggle | PRESENT | Win32IDE_SearchPanel.cpp | std::regex |
| Result list with file:line | PRESENT | Win32IDE_SearchPanel.cpp | Double-click opens file |
| 2000 result cap | PRESENT | Win32IDE_SearchPanel.cpp | goto done |
| Background search thread | PRESENT | Win32IDE_SearchPanel.cpp | std::thread detach |
| Replace in files | MISSING | — | Not implemented |
| Fuzzy file search (Ctrl+P) | MISSING | Win32IDE_FuzzySearch.cpp listed in missing-225 | Source file absent |
| Symbol search (Ctrl+T) | MISSING | — | Not implemented |
| Command palette (Ctrl+Shift+P) | MISSING | — | Not implemented |


---

## Section 13: Settings / Configuration

| Feature | Status | Source | Notes |
|---|---|---|---|
| Settings persistence | PRESENT | Win32IDE_Settings.cpp | Exists in source |
| Settings GUI | PRESENT | Win32IDE_SettingsGUI.cpp | Exists in source |
| Keyboard shortcut editor | MISSING | Win32IDE_ShortcutEditor.cpp listed in missing-225 | Source file absent |
| Theme selector | MISSING | Win32IDE_Themes.cpp listed in missing-225 | Source file absent |
| Font size configuration | MISSING | — | Hardcoded 16px mono |
| Tab size / spaces vs tabs | MISSING | — | Not implemented |
| Auto-save | PRESENT | Win32IDE_AutoSave.cpp | Exists in source |
| Workspace settings | MISSING | — | No .rawrxd/settings.json equivalent |

---

## Section 14: Keyboard Shortcuts

| Feature | Status | Source | Notes |
|---|---|---|---|
| Ctrl+S (save) | PARTIAL | Win32IDE_Commands.cpp | Exists; wiring to EditorEngine_SaveFile not confirmed |
| Ctrl+Z / Ctrl+Y (undo/redo) | MISSING | — | No undo stack |
| Ctrl+F (find) | PARTIAL | Win32IDE_Commands.cpp | Command registered; dialog not confirmed |
| Ctrl+P (fuzzy file open) | MISSING | — | FuzzySearch source absent |
| Ctrl+Shift+P (command palette) | MISSING | — | Not implemented |
| Ctrl+` (toggle terminal) | MISSING | — | Not implemented |
| F5 (run/debug) | MISSING | — | Not implemented |
| F12 (go to definition) | MISSING | — | Not implemented |
| Alt+F4 (close) | PRESENT | main_win32.cpp | Standard Win32 WM_DESTROY |
| Tab (accept ghost text) | MISSING | — | Not wired in EditorWndProc |
| Escape (dismiss ghost text) | MISSING | — | Not wired in EditorWndProc |

---

## Section 15: Deep2 / Local Inference Integration

| Feature | Status | Source | Notes |
|---|---|---|---|
| Model load from path | PRESENT | Deep2Engine.cpp | /load path wired in CLI |
| GGUF metadata discovery | PRESENT | gguf_loader.cpp | Architecture, tensors, quant |
| CPU inference (AVX2/AVX-512) | PRESENT | cpu_inference_engine.cpp | Native kernels |
| Vulkan GPU inference | PRESENT | vulkan_compute.cpp | Compute pipeline |
| Multi-GPU scheduling | PRESENT | Deep2Engine.cpp | Heterogeneous device lanes |
| Streaming token output | PRESENT | Deep2Engine.cpp | generateStream() |
| KV cache reset between generations (D2) | PRESENT | Deep2Engine.cpp:3671 | Measured PASS in Batch 01 |
| Result-state contract (D1) | PARTIAL | Deep2Engine.cpp:4118 | ForwardFailure+completed=true still reachable |
| EOS/control token termination (D3) | PARTIAL | Deep2Engine.cpp | Implemented, not proven |
| sampler topP / repeatPenalty / minP / seed | MISSING | Deep2Engine.h:297-309 | 4 of 7 GenerationOptions fields are dead writes |
| IDE chat → Deep2 streaming | PARTIAL | Win32IDE_AgenticBridge.cpp | Echo path; real gate not called |
| Model selector UI | MISSING | Win32IDE_ModelDiscovery.cpp listed in missing-225 | Source file absent |
| Model download / management | MISSING | — | Not implemented |
| Token budget / context length display | MISSING | — | Not implemented |
| Live VRAM budget display | PARTIAL | Deep2Engine.cpp | Telemetry exists; not surfaced in IDE UI |

---

## Section 16: CMake / Source Coverage Gaps (from RAWRXD_IDE_CMAKE_FULL_AUDIT_001)

These are structural gaps that block full IDE compilation and certification.

| Gap | Measurement | Status |
|---|---|---|
| WIN32IDE_SOURCES missing paths | 225 distinct paths | OPEN |
| Unbound implementation files | 1271 files | OPEN |
| Ambiguous bindings | 81 files | OPEN |
| Missing-but-bound references | 360 references | OPEN |
| Orphan CMakeLists.txt trees | 7 trees | OPEN |
| Unreachable targets | 17 targets | OPEN |
| Dead add_subdirectory() calls | 4 (runtime/tests/tools/validation) | OPEN |
| rawr_main.cpp absent (85 CLI sources silently dropped) | Confirmed | OPEN |
| win32ide_strict unreachable from root | Confirmed | OPEN |
| Deep2 D1 result-state contract | ForwardFailure+completed=true reachable | OPEN |
| Deep2 D3 EOS termination | Implemented, not proven | OPEN |
| IDE clean shutdown (no forced kill) | Not demonstrated | OPEN |
| IDE chat → real Deep2 token stream | Not demonstrated | OPEN |

