# Win32 IDE Language-Capacity Matrix (evidence-based, 2026-10-13)

Source: static audit of the only building IDE target (`RawrXD-Win32IDE-Native`,
`src\win32app\Win32IDE.cpp` + 22 modules) plus `src\` language infrastructure.
Method: module-by-module reachability from the live target; zero inferred capability.

## Verdict

The building IDE has **39 file-extension labels with NO per-language engine behind them**:

| Capability                 | Live win32app evidence                                                                 |
| -------------------------- | -------------------------------------------------------------------------------------- |
| Extension → label map      | ✅ 39-42 mappings (`Win32IDE_VSCodeUI.cpp:810-877`) — display only                      |
| Syntax keyword tables      | ❌ 0 keyword tables found in the building target                                        |
| Tokenizer/highlight engine | ❌ none reachable from the live target (legacy `src\ide\` trees are orphaned)           |
| Completion/IntelliSense    | ❌ `real_time_completion_engine_v2.cpp:261,313` = `return realistic mock data`          |
| Diagnostics/LSP            | ❌ `src\lsp\`, `lsp_client.cpp`, `language_server_integration.cpp` - not in target       |
| Navigation/refs            | ❌ no semantic index reachable (`src\semantic_index\` orphaned)                          |
| Debugging                  | ❌ `Win32IDE_Debugger.cpp` = panel shell; 0 Win32 debug API calls (no CreateToolhelp32Snapshot / WaitForDebugEvent / ContinueDebugEvent) |
| Refactoring                | ❌ none                                                                                  |
| Build/compile integration  | ✅ REAL but C/C++-only: `Win32IDE_Build.cpp` drives cl/link via the repo's own MSVC path |
| Inference binding          | ✅ REAL: `CPUInferenceEngine` (per-file dequant + logits), agent bridge = stub (StartAgentLoop → false) |

## The "61+ languages" claim origin

`compilers\INTEGRATION_COMPLETE.md` = a ROADMAP TODO ("61+ Languages ???" =
planned compiler-targets list), echoed into promotion docs. The claim was never a language-intelligence claim.

## Defensible language-support statement

- **39 extension labels** (display).
- **C/C++** first-class end-to-end (the IDE's own build/compile path + agent fixture).
- **0 additional languages with live language services.**
- Legacy/roadmap sources claim 61+ compiler families and shipped grammar tables in orphaned trees (`src\ide\`, `Consolidated_Modules_*`, `Advanced_Reverse_Engineered\src`) — salvage inventory, not shipped capability.

## Gate 4 acceptance contract (to be met, not claimed)

1. Win32 LSP host process (real JSON-RPC client over stdio/named-pipe).
2. didOpen/didChange → real diagnostics surfaced in the IDE UI.
3. Completion/navigation certified for ≥3 languages via REAL servers (clangd / basedpyright / jdtls or the LSP host's own engine).
4. References or go-to-def proof on a real repo.
5. Integration tested in the live target build, receipts saved under `evidence\`.
