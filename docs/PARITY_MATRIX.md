# Capability parity matrix (not a 134-item inventory)

Legend: IMPLEMENTED = source in this drop; INTEGRATE = expected existing RawrXD component requires wiring and tests; MISSING = not implemented here.

| VS Code / extension family | State | Work required |
|---|---|---|
| read/readFile | IMPLEMENTED | JSON tool schema + IDE bridge |
| search/listDirectory | IMPLEMENTED | pagination + ignore rules |
| search/fileSearch | IMPLEMENTED | glob semantics + index |
| search/textSearch | IMPLEMENTED | ripgrep-equivalent semantics and cancellation |
| edit/createDirectory | IMPLEMENTED | user-facing diff/approval |
| edit/createFile | IMPLEMENTED | undo/rollback |
| edit/editFiles | PARTIAL | multi-hunk patches and transaction support |
| execute/runInTerminal | PARTIAL (Windows) | sandbox, cancellation, PTY, process-tree cleanup |
| read/problems | MISSING | diagnostics bridge |
| search/changes | MISSING | Git diff provider |
| search/codebase | MISSING | semantic index |
| search/usages | MISSING | C++ language server/symbol graph |
| execute/createAndRunTask | MISSING | task engine |
| execute/getTerminalOutput | MISSING | session capture |
| execute/testFailure | MISSING | test results adapter |
| agent/runSubagent | MISSING | isolated context + bounded delegation |
| todo | MISSING | task state persistence |
| vscode/* | MISSING | native IDE command mapping |
| web/fetch | MISSING | WinHTTP with URL trust and limits |
| browser/* | INTEGRATE | existing browser authority + DOM/capture tests |
| CMakeTools eight visible entries | MISSING | native CMake/CTest provider, C++ symbol index |
| PowerShell group | UNKNOWN | actual tool names required |
| Python group | UNKNOWN | actual tool names required |
| User Defined Tool Sets | UNKNOWN | actual definitions required |
| MCP tools | MISSING | JSON-RPC stdio/HTTP transport + initialization/discovery |
| GitHub tools | MISSING | authenticated API integration |
| Ollama/Deep2 unified agent tool bridge | MISSING | model adapters and tool-call execution |

**Acceptance:** inventory all 134 selected entries; execute a deterministic per-tool contract test against the same workspace and compare effects and responses; record PASS/FAIL/NOT RUN with hashes and logs. 100% means all 134 contracts pass, not merely that tool names are registered.
