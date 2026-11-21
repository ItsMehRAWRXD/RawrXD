# Agentic IDE workstream (G46–G57) — consolidated status (2026-11-21)

## Closed with runtime evidence
| Gate | Evidence |
| --- | --- |
| G46 Authorized tool execution | `06582a9059` — host `read_file` (ok=true), answer = exact fixture token |
| G47 Autonomous edit/build/test/repair | `8a356c76af` — edit→build→test converged, `100% tests passed` |
| G48 Acceptance evaluator | `f1b0c7b4ae` — rejects ungrounded success + build-fail; accepts verified pass |
| G49 LSP protocol | `7f3880d2f5` — initialize/didOpen/completion/hover/definition/didSave/diagnostics all real |
| G54 Layout persistence | `56daede7de` — normal+maximized restore; position restores, size overridden by layout |
| G55 Native Git | `dac2a6113a` — menu IDs 3020-3024 + real git add/commit/push/pull/status |
| G56 Ollama health | `f7719c2a21` — HTTP 200 + reachable:yes |
| G57 Ollama tool+repair | `233c5dbb53` — full Ollama edit/build/run_shell chain, exit=0 |

## Implemented, runtime acceptance pending (GUI-heavy)
| Gate | Source | Remaining |
| --- | --- | --- |
| G50 Debugger | `Win32NativeDebugBackend.cpp`, `Win32IDE_Debugger.cpp` | launch/breakpoint/step/inspect via GUI |
| G51 GhostText | `Win32IDE_GhostText.cpp`, `V280Bridge_Impl.cpp` | render/accept/dismiss/cancel with live model |
| G52 Output/Problems | build dispatch fixed (`b0b97f5213`), Output tee (`8715414ffb`), C2065 verified, stale clearing (`e84b87419a`) | Problems item text/severity + double-click navigation |
| G53 Debug Console | debugger backend | command execution in active session |

## Key production fixes this session
- `b0b97f5213` — build output teed into Output pane (thread-safe `OutputToPane`).
- `8715414ffb` — Output pane C2065 with file/line/col verified.
- `e84b87419a` — stale diagnostics cleared after corrected rebuild.
- `2ab93fa30e` — shared GPU-compute link restored (quant_dot_dispatch into rawrxd_gpu_compute).

## Reconfirmation (this turn)
- `rawr lsp probe`: `caps=1 completions=1 hover=1 definitions=1 diagnostics=1 rename_edits=1 code_actions=1 symbols=4 SESSION_REAL=1`.
- `GET /api/tags` -> 200; `rawr backend status` -> selected=ollama, routable=yes.

## Ledger
```
G46=PASS, G47=PASS, G48=PASS, G49=PASS, G54=PARTIAL, G55=PASS, G56=PASS, G57=PASS
G50/G51/G52/G53=IMPLEMENTED_RUNTIME_PENDING
AGENTIC_IDE_CLOSED=8 of 12
```