# COLLAB_FOLDER_AUDIT.md

## Folder: `src/collab/`

### Summary
Full collaboration subsystem for the RawrXD IDE: Live Share sessions, shared terminals,
AI-assisted pair programming, CRDT-based real-time editing, cursor/presence tracking,
and WebSocket transport. All Win32-native, no Qt, no external dependencies.

### Contents

#### Core Infrastructure (existing, now with headers)
- `crdt_buffer.h/.cpp`: CRDT logic for real-time multi-user editing and conflict resolution.
- `cursor_widget.h/.cpp`: Collaborative cursor display and synchronization (Win32 native).
- `websocket_hub.h/.cpp`: RFC 6455 WebSocket server for real-time collaboration transport.

#### Live Share Session
- `LiveShareSession.h/.cpp`: Host/join/leave lifecycle, session tokens, permission model
  (Owner/Editor/ReadOnly), participant tracking, CRDT-based file sync, cursor/presence
  broadcasting, session chat, heartbeat monitoring.

#### Shared Terminals
- `SharedTerminal.h/.cpp`: Terminal multiplexer for shared sessions. Permission-based
  input control (None/Input/Admin), output broadcast, scrollback sync, resize support.

#### Pair Programming AI
- `PairProgrammingAI.h/.cpp`: Driver/Navigator role management with auto-assignment.
  AI suggestions (completions, refactors, bug warnings, conflict resolution, review
  comments, next-step hints). Conflict detection for overlapping edits. LLM integration
  hook for live inference. Activity tracking and combined context prompts.

#### Orchestrator
- `CollaborationManager.h/.cpp`: Top-level manager wiring LiveShareSession, SharedTerminal,
  PairProgrammingAI, and CursorWidget. Tick thread for heartbeats and conflict detection.
  Full callback model for IDE integration.

#### Agent Tools
- `CollabToolHandlers.h/.cpp`: 18 agentic tools for programmatic collaboration control
  (host/join/leave, share/edit files, list participants, chat, create/manage terminals,
  pair programming, AI suggestions, code review, diagnostics). OpenAI function-calling
  schema generation.

### Dependency Status
- **No external dependencies.**
- All CRDT, WebSocket, presence, terminal mux, and AI pair programming logic is in-house.
- nlohmann/json used for structured message serialization (already a project dependency).

### Integration Points
- `AgenticIDE`: CollaborationManager registered as a component (`m_collabManager`).
- `AgentToolHandlers`: 18 collab tools registered in dispatch table + schema merged.
- `Win32IDE_Collab.cpp`: UI panel for hosting/joining sessions (uses same transport).
- `CMakeLists.txt`: All new .cpp files listed in the Win32IDE build target.

### Audit Status
- **Implementation: 100% complete.**
- All collaboration features implemented: Live Share, shared terminals, pair programming AI.
- Thread-safe with mutexes, no exceptions, structured Result/ToolCallResult patterns.
