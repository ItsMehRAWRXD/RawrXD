# AGENT_ARCH_AUDIT_001 — Fable→RawrXD Capability Matrix

**Primary tree:** `F:\rawrxd`  
**Mode:** READ-ONLY audit (matrix files are the only writes)  
**Laws:** `SOURCE_WIRED != RUNTIME_REACHED` · `NOT_RUN != PASS` · `CERTIFIED=0` · `PROMOTE=0` · `TIP_CLIMB=HOLD`

---

## Fable extraction docs / evidence

| Path | Role |
|------|------|
| `F:\rawrxd\FEATURE_GAP_REGISTER.md` | **Primary claim source** — AF01–AF07 agent features (Batch 3/6) |
| `F:\rawrxd\docs\IDE_NOT_CAPABLE_AUDIT.md` | Agent/model routing incapability audit |
| `F:\rawrxd\docs\archive\AUTONOMOUS_AGENT_IMPLEMENTATION_ROADMAP.md` | Historical roadmap cross-check |
| `F:\rawrxd\3rdparty\r9700-stack\notes\review-fable.md` | Named “Fable” but **GPU/kernel review only** — not agent-arch extract |
| `evidence/**` Fable-named agent extract | **Not found** (no `*Fable*` agent-arch seal under evidence/) |

No sealed Fable agent-architecture extract claiming PASS/PROMOTE was located. Claims below map FEATURE_GAP AF* expectations to live `F:\rawrxd` sources.

---

## Capability matrix

| name | fable_claim | source_wired | runtime_reached | key rawrxd paths |
|------|-------------|--------------|-----------------|------------------|
| AgentExecutor | AF01 executor entry | **false** (stub) | false | `Win32IDE_AgentExecutor.cpp/h` (CMake-listed) |
| PlanningLoop | AF02 plan→execute | **false** | unknown | `Win32IDE_AutonomousLoop.h` (no .cpp); `Win32IDE_PlanExecutor.cpp` (not in CMake); `SelfRepairLoop.*` (agentic target) |
| StateMachine | AF03 pending/running/waiting/done/error | **false** | unknown | `agent_loop.hpp` AgentState; `Win32IDE_AgentStepTimeline.*` (UI chips) |
| ToolCalling | AF01 registry+dispatch | **true** | unknown | `rawr_core` ToolRegistry; `Win32IDE_AgentCommands.cpp`; `ToolCallBridge.h`; ComputerUse `RegisterTools` |
| AgentHistory_TaskLedger | AF05 undo + durable ledger | **false** | unknown | `Win32IDE_AgentHistory.cpp`; `AgentSession.*`; `PersistentTaskBacklog.cpp` |
| AgenticBridge | AF07 bridge/loop bridge | **true** | unknown | `Win32IDE_AgenticBridge.*`; `Win32IDE_AgenticLoopBridge.*` |
| SessionManagement_Cancellation | session + cancel | **true** | unknown | `AgentSession.*`; LoopBridge `Cancel`; `onAgenticLoopCancel` / `onDeep2Cancel` |
| SecurityBoundary | AF04 sandbox + AF06 approval | **false** | false | `ExtensionSandboxManager` (always-allow); `ConsentPrompt` (demo MessageBox) |
| ModelProviderAbstraction | Ollama/GGUF/Vulkan/Strata/Cloud | **true** (partial) | unknown | `BackendRouter` Deep2+Ollama; `ollama_client`; Deep2 GGUF+Vulkan; Strata KV/residency; cloud held false |

Machine-readable twin: `CAPABILITY_MATRIX.json` (fields: `name`, `fable_claim`, `rawrxd_paths[]`, `source_wired`, `runtime_reached`, `gaps[]`, `evidence_refs[]`).

---

## Counts

| Metric | Value |
|--------|-------|
| Capabilities inventoried | 9 |
| **SOURCE_WIRED=true** | **4** (ToolCalling, AgenticBridge, SessionManagement_Cancellation, ModelProviderAbstraction) |
| **SOURCE_WIRED=false** | **5** (AgentExecutor, PlanningLoop, StateMachine, AgentHistory_TaskLedger, SecurityBoundary) |
| Merely-present / not product-wired highlights | AgentExecutor stub, AutonomousLoop.h-only, PlanExecutor (no CMake), always-allow sandbox, ConsentPrompt demo, AgentState enum unused as SSOT |

`SOURCE_WIRED != RUNTIME_REACHED`. No capability in this audit is marked PASS from runtime. `NOT_RUN != PASS`.

---

## Top 10 gaps (blocking severity)

1. **No product-wired Planning & Execution Loop (AF02)** — AutonomousLoop header-only; PlanExecutor absent from CMake → blocks multi-step autonomy.  
2. **AgentExecutor always-true stub** while CMake-listed → invents success.  
3. **Sandbox always-allows** path/command → blocks safe autonomy (AF04).  
4. **Approval not on tool-dispatch choke point** — ConsentPrompt is a demo dialog (AF06).  
5. **Fragmented ToolRegistry surfaces** (CLI / agentic / ComputerUse / AgentCommands) → inconsistent permissions.  
6. **No execution StateMachine SSOT** — UI timeline + enums only (AF03).  
7. **AgentHistory undo does not restore file bytes** (AF05).  
8. **Dual AgenticBridge + AgenticLoopBridge** without single runtime owner.  
9. **IDE agent path historically bypasses BackendRouter/Ollama for tools** → provider abstraction incomplete on product loop.  
10. **AgentSession / PersistentTaskBacklog not proven RUNTIME_REACHED** as IDE product TaskLedger.

---

## Future consolidation targets (identify only — do not implement)

1. **Unified Autonomous Agent Runtime** — one driver over Bridge + LoopBridge + SelfRepairLoop/agent_loop.  
2. **Single ToolRegistry SSOT** — one dispatch + policy choke point.  
3. **Canonical PlanningLoop** — one implemented loop; retire dead PlanExecutor until cleaned.  
4. **TaskLedger SSOT** — AgentSession + PersistentTaskBacklog; AgentHistory as undo adapter only.  
5. **SecurityBoundary** — real path/command policy + approve/deny inside dispatch.  
6. **ModelProvider facade** — BackendRouter for Deep2/Ollama; GGUF/Vulkan under Deep2; Strata as residency/KV; cloud remains held-false unless explicitly authorized later.

---

## Disposition

```
CERTIFIED=0
PROMOTE=0
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
```
