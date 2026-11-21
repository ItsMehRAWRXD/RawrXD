# Agentic IDE gates G49–G55 — implementation + runtime status (2026-11-21)

G54 and G55 are runtime-confirmed (see `GATE_G54_G55_LAYOUT_GIT.md`). G49, G50,
G51, G52, G53 are implemented; their full runtime acceptance requires driving
the native IDE UI (open a file, trigger completion, set a breakpoint, etc.),
which is GUI-interaction-heavy.

## G49 — LSP completion and diagnostics => implemented
- `src/lsp/RawrXD_LSPServer.cpp` is a full stdio JSON-RPC 2.0 server with
  `main()` (line 1637) handling `initialize`, `textDocument/completion`,
  `hover`, `definition`, `references`, `documentSymbol`,
  `semanticTokens/full`, and `textDocument/publishDiagnostics`.
- `Win32IDE_LSPServer.cpp` bridges it into the IDE with menu commands
  (start/stop/status/reindex/diagnostics/publish, IDs 9200-9208).
- Runtime closure: launch the embedded LSP server (or a standalone build) and
  send `initialize` + `textDocument/didOpen` + `completion`; expect a real
  completion result and a `publishDiagnostics` notification.

## G50 — Debugger => implemented (to runtime-verify)
- Debugger launch/breakpoint/stepping exist in the IDE command surface. Runtime
  closure: launch a debug session, set a breakpoint, step, inspect a variable.

## G51 — GhostText inline completion => implemented
- `V280Bridge_Impl.cpp` + `IV280Bridge` + ghost-text buffer provide inline
  completion (reads from a suggestion buffer, renders on WM_PAINT).
- Runtime closure: trigger a suggestion and observe the inline ghost text +
  accept/reject.

## G52 — Output / Problems panes => implemented
- `Win32IDE.cpp` bottom panel: Terminal, Output, Problems, Debug Console.
  Build errors/warnings become navigable Problems entries.
- Runtime closure: build, observe Output + Problems population.

## G53 — Debug Console => implemented
- Debug Console pane exists in the bottom panel.
- Runtime closure: execute a command in an active debug session.

## Summary
| Gate | Status |
| --- | --- |
| G49 LSP | implemented, runtime-pending (needs LSP client interaction) |
| G50 Debugger | implemented, runtime-pending |
| G51 GhostText | implemented, runtime-pending |
| G52 Output/Problems | implemented, runtime-pending |
| G53 Debug Console | implemented, runtime-pending |
| G54 Layout | **PASS** (session.json runtime-confirmed) |
| G55 Git | **PASS** (Git menu IDs 3020-3024 runtime-confirmed) |

Full runtime closure of G49–G53 requires scripted GUI interaction (open file,
trigger completion/breakpoint), which is the next step. G54/G55 are done.