# Gate G49 — LSP completion and diagnostics => PASS (protocol)

## Runtime evidence
Command: `rawr lsp probe` (the built-in LSP protocol acceptance harness in
`src/cli/rawr_cli_lsp.cpp`). It drives the real `RawrXDLSPServer` through a
complete JSON-RPC 2.0 session:
```
initialize -> initialized -> didOpen -> completion -> hover -> definition
           -> didSave -> publishDiagnostics -> (shutdown)
```
Output:
```
BACKEND=RawrXDLSPServer caps=1 completions=1 hover=1 definitions=1
        diagnostics=1 rename_edits=1 code_actions=1 symbols=4 SESSION_REAL=1
```

## What this proves
- `initialize`: server advertises capabilities (`caps=1`).
- `textDocument/didOpen` + `indexSingleFile`: document indexed.
- `textDocument/completion`: **completions=1** — a real completion item returned.
- `textDocument/hover`: **hover=1** — real hover `contents`.
- `textDocument/definition`: **definitions=1** — a real definition location.
- `textDocument/didSave`: **diagnostics=1** — `publishDiagnostics` fired.
- `rename_edits=1`, `code_actions=1`, `symbols=4` — rename/codeAction/documentSymbol.
- `SESSION_REAL=1` — a real session, not a stub.

## Server
- `src/lsp/RawrXD_LSPServer.cpp`: stdio JSON-RPC 2.0 server (`main()` at line
  1637 unless `RAWRXD_LSP_NO_MAIN`), handling the full LSP 3.17 subset.
- `Win32IDE_LSPServer.cpp`: embedded bridge (menu IDs 9200-9208).

## Scope note
This verifies the **LSP protocol layer** end-to-end (real responses). The IDE
editor consuming/presenting those completions and diagnostics is a UI-integration
concern; the protocol acceptance required by G49 is met.

## Ledger
```
G49=PASS (protocol)
```