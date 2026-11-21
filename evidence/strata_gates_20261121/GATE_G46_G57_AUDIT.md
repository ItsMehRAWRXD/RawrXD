# Agentic IDE gates G46–G57 — audit + G56 closure (2026-11-21)

Completion rule: mark PASS only with observable runtime evidence. Source presence
alone is not certification. This pass closes **G56**; the remainder are
classified as implemented-but-runtime-pending or apparently unimplemented.

## G56 — Live Ollama registry health probing => PASS
Runtime evidence:
- `GET http://127.0.0.1:11434/api/tags` -> HTTP 200 (service UP).
- `rawr backend status` (selected=ollama) -> `active: ollama on 127.0.0.1:11434`,
  `reachable: yes` (live ping result, not an assumption).
- Note: the registry `health` column stays `unavailable` by design
  (`rawr_cli.cpp` comment: capabilities are not adapter-tested; a reachable
  server is not proof of chat/stream/tools/repair). Live connectivity probing is
  what G56 requires, and it is present.

## G46–G57 classification (source audit; runtime acceptance still required)
| Gate | Feature | Source present | Status |
| --- | --- | --- | --- |
| G46 | Native agentic tool execution | yes (agentic bridge / tool_call, 24 files) | implemented, runtime unverified |
| G47 | Autonomous edit/build/test/repair loop | yes (agentic loop) | implemented, runtime unverified |
| G48 | Native acceptance evaluator integration | to confirm | unverified |
| G49 | LSP completion and diagnostics | yes (`src/lsp/RawrXD_LSPServer.cpp`, CMakeLists:3436) | implemented, runtime unverified (needs editor + language backend) |
| G50 | Debugger launch/breakpoints/stepping | to confirm | unverified |
| G51 | GhostText inline completion | yes (18 files) | implemented, runtime unverified |
| G52 | Output and Problems panes | yes | implemented, runtime unverified |
| G53 | Debug Console | yes | implemented, runtime unverified |
| G54 | Docking and layout persistence | docking present (3 files); **no layout save/restore** (`SetWindowPlacement`/save/load absent) | partial / likely unimplemented |
| G55 | Native Git operations | **no Git integration matched** (`Git_`/`git_status`/RunGit = 0 files) | likely unimplemented |
| G56 | Live Ollama health probing | yes + runtime | **PASS** |
| G57 | Ollama tool and repair capabilities | to confirm | unverified |

## What remains for G46–G55, G57
Runtime acceptance requires driving the native IDE with a live model:
agentic tool execution, GhostText, LSP completion (with a language backend),
debugger, panes, and Ollama tool/repair. G54 (layout persistence) and G55 (Git)
appear to need implementation, not just testing.

## Updated ledger
```
G01=PASS
G56=PASS
G46_G55_G57=SOURCE_PRESENT_RUNTIME_PENDING (G54/G55 likely unimplemented)
REMAINING_AFTER_THIS_PASS=81
```