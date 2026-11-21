# Sprint 3 status — GUI backend selector — 2026-11-21

## Verdict

```
SPRINT_3=SELECTOR_AND_DISCOVERY_PASS__RUNTIME_ROUTING_OPEN
COMMIT=0fb2b37202 (selector) + 0f9a9b4d01 (model scan) + 249db218fb (link fix)
EXE_SHA256=8D1EC67224417CAC723DFB4F6A9680068ED1A1FE3AE4BB256C647B20DEABF3BD
```

## Verified

| Gate | Evidence |
|---|---|
| Backend combo 1226 created | `[BACKEND_SELECTOR_CREATE] parent=0x208D4 hwnd=0x2090E error=0` |
| Three entries, correct labels | `Deep2 (Vulkan)` / `Strata (Deep2 + residency)` / `Ollama (HTTP)` |
| Notification reaches handler | `[BACKEND_SELECTOR_NOTIFY] code=1` |
| Handler sees selection | `[BACKEND_SELECTOR_APPLY] sel=2 pref=ollama` |
| Preference written | `[BACKEND_PREF_OPEN] rc=0`, `[BACKEND_PREF_WRITE] written=6 ferror=0 close=0` |
| File-only restart restore | `sel=2 pref=ollama` with env vars removed |
| Model selector 1206 populated | `[MODEL_DISCOVERY_ADD] F:\rawrxd\models\*.gguf` (inventory scan) |
| Discovery targets correct control | `[MODEL_DISCOVERY_ENTRY] ctrlId=1206` |

## Open

| Gate | Status |
|---|---|
| Strata fail-closed chat | Guard compiled at the top of `generateResponseAsync`; not exercised end to end |
| Ollama GUI routing | Unverified |
| Backend resolution precedence | Request override → in-memory → persisted default not unified |
| Live Ollama health probe | Classifier committed (`18fa0ce852`); HTTP probe not wired |
| Diagnostics removal | 4 blocks remain in `Win32IDE.cpp`, `Win32IDE_lifecycle.cpp`, `Win32IDE_AgentCommands.cpp` |

## Root cause established for the earlier "empty combo"

`[MODEL_DISCOVERY_PATH] path='' forced=0` — no model source was configured, so the combo
kept its placeholder. Fixed by scanning `F:\rawrxd\models` when `m_availableModels` is empty
(`0f9a9b4d01`). Discovery itself was never broken.

## Why Strata is not routable

`SetStrataExpertTracking` / `SetStrataCachePolicy` / `SetStrataExpertPrefetch` are methods on
`RuntimeGraph::Executor` (`src/deep2/runtime_graph_executor.hpp`). `Deep2Engine` — used by
IDE chat via `Deep2Bridge` — has no Strata API. Strata is therefore a **graph-executor
execution mode**, not a third engine.

Making Strata serve IDE chat requires a chat route through `RuntimeGraphExecutor` with expert
tracking; `deep2_strata_chat` (`ce18c2a78c`) is the working template.

## Next

1. Strip the diagnostic blocks (the earlier regex attempt over-matched and broke the build;
  use function-scoped manual edits, one file at a time, rebuilding after each).
2. Run the Strata fail-closed chat with a GGUF selected.
3. Wire the registry health probe (`ClassifyOllamaProbe` + bounded `/api/tags`).
4. Then Option A: graph-executor chat route for Strata.

## Non-claims

No GUI Strata generation. No Ollama GUI response through RawrXD. No release certification.