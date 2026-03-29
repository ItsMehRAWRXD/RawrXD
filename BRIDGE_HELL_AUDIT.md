# Bridge Hell Audit — Win32IDE UI Propagation Failures
**Date:** 2026-03-24  
**Scope:** Features that exist in source but produce generic failure text or silently drop in Win32IDE UI.

---

## CATEGORY 1 — Bridge-Not-Initialized Hard Stops

These features have real handler code but **gate immediately** when `m_agenticBridge == null`, emitting a generic warning and never surfacing a result to the user.

| Feature | Command ID | File | Bail Text |
|---|---|---|---|
| Agent Workflow (One Shot) | 5906 | Win32IDE_Commands.cpp:3099 | `[AgentWorkflow] Agent bridge not initialized.` |
| Agent Tool Chain (One Turn) | 5914 | Win32IDE_Commands.cpp:3344 | `[AgentToolChain] Agent bridge not initialized.` |
| Auto-Fix Top Diagnostic | 5928 | Win32IDE_Commands.cpp:3861 | `[AutoFixDiag] Agent bridge not initialized.` |
| Sub-Agent Todo List | 4112 | Win32IDE_AgentCommands.cpp:137 | `Agentic Bridge not initialized` |
| Sub-Agent Todo Clear | — | Win32IDE_AgentCommands.cpp:158 | `Agentic Bridge not initialized` |
| Sub-Agent Status | — | Win32IDE_AgentCommands.cpp:172 | `Agentic Bridge not initialized` |
| Agent View Status | 4104 | Win32IDE_AgentCommands.cpp:1336 | `Agentic Bridge not initialized` + MB |
| Async Chat Inference | — | Win32IDE.cpp:6033 | `Error: Agentic Bridge not initialized.` via callback |
| Circular Beacon Dispatch | — | CircularBeaconSystem.cpp:454 | `Bridge not initialized` (struct return) |
| Autonomy Action Execute | — | Win32IDE_Autonomy.cpp:183 | **SILENT DROP** — LOG only, no UI feedback |
| MCP Orchestrator Handlers | — | mcp_hooks.asm:70482 | `AgenticOrchestrator: handler not implemented` |

**Root cause:** `m_agenticBridge` not pre-initialized before these paths are hit.  
**Known fix pattern:** See `/memories/repo/agentic_bridge_reinit_fix.md` — call `initializeAgenticBridge()` before surfacing the error; pre-init on `HandleCopilotSend` path.

---

## CATEGORY 2 — Dead / Misrouted Menu IDs

### Build Menu Routing Bug
`resource.h` defines `ID_BUILD_*` (7001–7006) under the build menu, but `routeCommand()` routes the range `7000–8000` to **`handleHelpCommand()`**, not `handleBuildCommand()`. The actual build command handler uses IDs `10400–10402`. Result: every build menu item silently falls into the help handler and does nothing.

| Resource ID | Label | Routed To | Should Route To |
|---|---|---|---|
| 7001 `ID_BUILD_COMPILE` | Compile | `handleHelpCommand` | `handleBuildCommand` (10400+) |
| 7002 `ID_BUILD_BUILD` | Build | `handleHelpCommand` | `handleBuildCommand` |
| 7003 `ID_BUILD_REBUILD` | Rebuild | `handleHelpCommand` | `handleBuildCommand` |
| 7004 `ID_BUILD_CLEAN` | Clean | `handleHelpCommand` | `handleBuildCommand` |
| 7005 `ID_BUILD_RUN` | Run | `handleHelpCommand` | `handleBuildCommand` |
| 7006 `ID_BUILD_DEBUG` | Debug | `handleHelpCommand` | `handleBuildCommand` |

### View Menu IDs with No Handler Cases
These IDs fall into `handleViewCommand()` but have no `case` in the switch — they silently no-op:

| Resource ID | Label |
|---|---|
| 3030 `ID_VIEW_SYNTAX_HIGHLIGHTING_TOGGLE` | Syntax Highlighting Toggle |
| 3031 `ID_VIEW_VISION_ENCODER` | Vision Encoder |
| 3032 `ID_VIEW_SEMANTIC_INDEX` | Semantic Index |

---

## CATEGORY 3 — Feature Manifest Gaps (enterprise_license_v2.cpp)

Features declared in `g_FeatureManifest` with `implemented=false` or `wiredToUI=false` — these are entirely absent from the UI because the license gate rejects them before dispatch.

### Professional Tier — Not Implemented / Not Wired
| Feature | implemented | wiredToUI |
|---|---|---|
| CUDA Backend | ❌ false | ❌ false |
| HIP Backend | ❌ false | ❌ false |

### Enterprise Tier — Not Implemented / Not Wired
| Feature | implemented | wiredToUI |
|---|---|---|
| Flash Attention | ❌ false | ❌ false |
| Speculative Decoding | ❌ false | ❌ false |
| Continuous Batching | ❌ false | ❌ false |
| GPTQ Quantization | ❌ false | ❌ false |
| AWQ Quantization | ❌ false | ❌ false |
| Priority Queuing | ❌ false | ❌ false |
| Rate Limiting Engine | ❌ false | ❌ false |
| RBAC | ❌ false | ❌ false |

### Enterprise Tier — Implemented but NOT Wired to UI
| Feature | Source |
|---|---|
| Model Comparison | model_comparison.cpp |
| Batch Processing | batch_processor.cpp |
| Custom Stop Sequences | inference_engine.cpp |
| Grammar-Constrained Generation | grammar_sampler.cpp |
| LoRA Adapter Support | lora_adapter.cpp |
| Response Caching | response_cache.cpp |
| Prompt Library | prompt_library.cpp |
| Export/Import Sessions | session_export.cpp |
| Model Sharding | model_sharding.cpp |
| Tensor Parallelism | tensor_parallel.cpp |
| Pipeline Parallelism | pipeline_parallel.cpp |
| Custom Quant Schemes | custom_quant.cpp |
| Multi-GPU Load Balance | multi_gpu_scheduler.cpp |
| Dynamic Batch Sizing | dynamic_batch.cpp |
| API Key Management | api_key_manager.cpp |

### Sovereign Tier — All 8 Features NOT Implemented / NOT Wired
Air-Gapped Deploy, HSM Integration, FIPS 140-2, Custom Security Policies, Sovereign Key Mgmt, Classified Network, Tamper Detection, Secure Boot Chain.

> **Note:** `enterprise_license.cpp` (the Release copy) marks most of these as `implemented=true, wiredToUI=true`, while `enterprise_license_v2.cpp` marks them false. The two manifests are **out of sync** — the v2 copy is what `FeatureRegistryPanel` reads at runtime.

---

## CATEGORY 4 — Win32IDE UI Feature Manifest Gaps (Win32IDE_FeatureManifest.cpp)

Features where the Win32 column is `FeatureStatus::Missing` — clicking their menu items either has no handler or outputs nothing useful:

### Vision Encoder (all 5 — fully unwired)
`vision.load`, `vision.encode`, `vision.describe`, `vision.extractCode`, `vision.analyzeDiagram`
→ All registered to command ID 0, no menu case exists.

### Semantic Index / Code Intelligence (all 5 — fully unwired)
`semantic.index`, `semantic.search`, `semantic.goto`, `semantic.references`, `semantic.hierarchy`
→ Command ID 0, no menu case. IDs 3031/3032 exist in resource.h but are dead (see Category 2).

### Ghost Text Completion
`streaming.ghostText` — `wiredToUI=false` for Win32 column. Ghost text state variables exist in Win32IDE but the trigger path from editor caret events is missing.

### Decompiler View (4 features)
`decomp.d2dView`, `decomp.syntaxColor`, `decomp.syncSelection`, `decomp.varRename`
→ All Win32 status Missing despite having IDs 4316–4318.

### WebView2 / Monaco (all 9 features)
`webview2.container`, `webview2.monaco`, `webview2.themes`, `webview2.msgbridge`, `webview2.devtools`, `webview2.zoom`, `webview2.sync` — Win32 status Missing. The WebView2 crash (0xC0000374) at runtime makes these unreachable.

### LSP Server (all 10 features)
`lsp.server.*` — All Win32 status Missing; LSP server exists in code but has no UI entry point wired.

### Session Save/Restore
`session.save`, `session.restore` — Win32 status Missing for both.

### PowerShell Panel
`ps.execute`, `ps.panel`, `ps.rawrxdModule` — Win32 status Missing; PS execution goes through terminal but no dedicated panel.

### Headless Mode (6 features)
`headless.mode`, `headless.server`, `headless.repl`, `headless.singleshot`, `headless.batch`, `headless.json` — all Win32 Missing (headless is CLI-only, no IDE integration).

### LSP ↔ AI Bridge
`lsp.aiBridge` — Win32 Missing; LSP client exists but AI routing path is unimplemented.

---

## CATEGORY 5 — Audit Dashboard Generic Output

`Win32IDE_AuditDashboard.cpp::cmdAuditDetectStubs()` — after scanning all features, shows only a generic `MessageBoxW` "Stub Detection Complete: N stubs found" with no actionable editor integration, no source-jump capability, and no live highlight of stub callsites.

---

## CATEGORY 6 — Silent Drops / Log-Only Failures

| Location | Failure Pattern |
|---|---|
| `AutonomyManager::executeAction()` | Logs `"Bridge not initialized; cannot execute action"` but shows **nothing** in UI output panel |
| `Win32IDE_AgentCommands.cpp:onAgentViewStatus` | Shows `MessageBoxA` generic text instead of live status |
| `mcp_hooks.asm` orchestrator handlers | Returns failure code 0 silently (MASM `szOrchNotImpl` path never surfaces to output) |
| `CircularBeaconSystem::dispatch()` error struct | Struct result checked by callers inconsistently — several callers don't propagate the `"Bridge not initialized"` error message to the output panel |

---

## PRIORITY RANKING

| Priority | Item | Fix Scope |
|---|---|---|
| P0 | Build menu routing bug (7001-7006 → helpCommand) | 1-line fix in `routeCommand()` |
| P0 | `AutonomyManager::executeAction()` silent drop | Add `appendToOutput()` call on bridge-null path |
| P1 | Bridge pre-init before all `m_agenticBridge` gate sites | Apply pattern from `agentic_bridge_reinit_fix.md` to 5906/5914/5928/onSubAgent* |
| P1 | View IDs 3030/3031/3032 — no handler cases | Add cases in `handleViewCommand()` |
| P2 | Manifest sync: enterprise_license_v2.cpp vs enterprise_license.cpp | Reconcile `implemented`/`wiredToUI` flags |
| P2 | `cmdAuditDetectStubs()` — generic MessageBox | Replace with source-linked output panel entries |
| P3 | Vision/Semantic/Decompiler/LSP features — all Win32 Missing | Requires full feature implementation pass |
