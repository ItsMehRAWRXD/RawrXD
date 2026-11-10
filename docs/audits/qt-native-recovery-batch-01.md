# Qt-to-native recovery audit — batch 01 (15 source targets)

Scope: repository code-search evidence, not an exhaustive dependency graph. **Presence of Qt code does not imply the shipping Win32 target links Qt.** No source removal, Qt vendoring, or new runtime dependency is authorized by this audit.

| # | Legacy source | Qt dependency observed | Native migration gate |
|---|---|---|---|
| 01 | `src/qtapp/main_qt.cpp` | QApplication | Compare startup, lifecycle, exception reporting with native Win32 entrypoint |
| 02 | `src/qtapp/MainWindow.h` | QMainWindow, QWebEngineView | Map each dock, command, browser, menu to native equivalent |
| 03 | `src/qtapp/MinimalWindow.h` | QMainWindow | Confirm native minimal-window recovery and smoke startup |
| 04 | `src/qtapp/MainWindow_v5.h` | QMainWindow | Compare later-generation UI commands and persistence |
| 05 | `src/qtapp/agentic_ide.h` | QMainWindow | Map agent controls to native IDE and end-to-end tool loop |
| 06 | `src/qtapp/terminal_pool.h` | QProcess, Qt widgets | Native CreateProcess/ConPTY lifecycle, cancellation and exit codes |
| 07 | `src/qtapp/ollama_proxy.h` | QNetworkAccessManager | Native HTTP request/stream/cancel/error parity |
| 08 | `src/qtapp/unified_backend.hpp` | QObject, QNetworkAccessManager | Concurrent Ollama/Deep2 backend routing and cancellation |
| 09 | `src/qtapp/ai_chat_panel.cpp` | QSyntaxHighlighter | Native chat transcript, streaming, selection, copy |
| 10 | `src/qtapp/widgets/masm_editor_widget.cpp` | QSyntaxHighlighter | Native assembly editing, diagnostics and syntax coloring |
| 11 | `src/qtapp/todo_dock.h` | Qt dock UI | Native task list, persistence and command binding |
| 12 | `src/qtapp/todo_manager.cpp` | QString and Qt persistence | Native task state and file format compatibility |
| 13 | `src/qtapp/settings.h` | QApplication initialization lifecycle | Native settings initialization and upgrade safety |
| 14 | `src/qtapp/telemetry.h` | QApplication initialization lifecycle | Native telemetry startup and shutdown safety |
| 15 | `src/qtapp/main_v5.cpp` | QFile, QTextStream | Native file I/O, UTF-8 and launch behavior |

## Release rules
1. Treat the original Qt sources as **read-only recovery references** until parity is proven.
2. Do not add Qt, nlohmann/json, third-party runtime libraries, or vendored dependencies.
3. Use Win32/Windows SDK/C++20 and existing repository source; CI runner tools are build-time infrastructure, not shipped dependencies.
4. For each target: identify live CMake inclusion, map actual functionality, implement missing native code, add regression tests, clean-build, then run the GUI or CLI witness.
5. Never count a Qt reference as a missing feature without checking the current native implementation.
6. Do not merge this branch into a divergent dirty checkout without provenance and review.

## Current verification boundary
- Code search identified the listed Qt references on the indexed default branch.
- This batch is **15 triage entries**, not 15 migrated components.
- Full source-file-by-source-file IDE audit, local Windows clean build, UI automation, and dual-GPU inference witnesses are still pending.
