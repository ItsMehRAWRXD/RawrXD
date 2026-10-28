# MATRIX â€” WIN32IDE_CLOSURE_MATRIX_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
PRIOR_TIP_SHA=C4FC9AE9A6EAC016A78B0C1BB1690B9C47A46A4B47FC51B1B807E10E14EDC43B
PRIOR_PRIOR_TIP_SHA=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F
ASOF_UTC=2026-10-28T11:25:00Z
AGENTIC_COMPOSER_RUNTIME_001=SEALED_INVOKED_SURFACE_RUNTIME_NOT_RUN
NO_INVENT_MET=1
SWARM_ORCH_SOURCE=SWARM_MODEL_ORCH_001
SWARM_IN_TIP=TIP_ABSORB_SWARM_002
HTTPTAGS_LINKED=1
SWARM_SELECTOR_SRC_NEWER_THAN_OBJ=0
SWARM_OLLAMA_HTTP_TAGS_OBJ=LINKED
```

Statuses: `MET` | `OPEN` | `HELD` | `BLOCKED` | `SOURCE` | `SOURCE_WIRED` | `RUNTIME_REACHED` | `RUNTIME_PARTIAL`  
Rule: cite required for MET/BLOCKED/HELD/RUNTIME_REACHED/RUNTIME_PARTIAL; SOURCE = local wiring/finding only; RUNTIME_REACHED â‰  MET; RUNTIME_PARTIAL â‰  MET.

## A01â€“A15 Release-blocking gates

| ID | Gate | Status | Cite / note |
|----|------|--------|-------------|
| A01 | Binary provenance (hash + CMake snapshot/commit + build logs + MAP/PDB) | **MET** | Earned on tip `6832F439â€¦`: `WIN32IDE_BINARY_PROVENANCE_003` (EXE/map/PDB + SWARM Selector/HttpTags/SubAgent + prior absorb pile in map + ninja/cmake from `TIP_ABSORB_SWARM_002`). `WIN32IDE_BINARY_PROVENANCE_002` HISTORICAL (C4FC9AE9 FAIL_CLOSED). `WIN32IDE_BINARY_PROVENANCE_001` historical (866E9D1B). Sibling A01 agent `331f85bf` SUPERSEDED. |
| A02 | Camellia `self_test=-8` RFC KAT | **BLOCKED** | `CAMELLIA_SELFTEST_RFC_001` = BLOCKED_DOCUMENTED; HMAC independent PASS; not invent-pass |
| A03 | Post-fix tip seal (LIVE_TETRAD + TOKEN64 + MULTI_FAMILY on EXE SHA) | **MET** | Earned on `6832F439â€¦`: `LIVE_TETRAD_POST_SWARM_ABSORB_001` PASS; `TOKEN64_PRODUCT_RUN_005` PASS (`TPS_PRODUCT_SEAL=1`); `MULTI_FAMILY_PRODUCT_005` PASS (gemma3). Priors on `C4FC9AE9â€¦`/`866E9D1Bâ€¦` historical only |
| A04 | Agent bridge + Watchdog product GUI/headless runtime same SHA | **OPEN** | Headless `/api/tool` lifecycle on tip `6832F439â€¦` in `AGENT_LIFECYCLE_TIP_001` (GUI bridge NOT_RUN) â€” full GUI+headless same-SHA breadth not earned |
| A05 | No fabricated tool success | **RUNTIME_PARTIAL** | `TOOL_ACTION_STATUS_E2E_002`: /api/tool success+failure PASS; cancel latch PASS; GateStub NEG PASS; Admit consumer SOURCE+unit PASS but tip Admit NOT_LINKED (RELINK_REQUIRED); A05_MET=0; prior `TOOL_ACTION_STATUS_RUNTIME_001` |
| A06 | Safe file writes (atomic/preview/rollback/deny) | **RUNTIME_REACHED** | Deny earned: `SAFE_WRITE_APPROVAL_TIP_001` tip `6832F439…` (abs/../UNC 403 + inside 200; FS OUTSIDE=0) — deny rows sealed/untouched. Atomic/preview/rollback: `SAFE_WRITE_ATOMIC_001` SOURCE_WIRED (`SafeWriteAtomic`/`SafeWriteRollback` TUs; write_file → tmp+ReplaceFile; Phase10-independent rollback; tools safe_write_*); RELINK_REQUIRED; RUNTIME NOT_RUN on tip binary. MET=0 |
| A07 | Tool approval + isolation / injection negatives | **RUNTIME_REACHED** | `SAFE_WRITE_APPROVAL_TIP_001` tip `6832F439â€¦`: no-key 401, evil Origin 403, exec without `RAWRXD_IDE_EXEC_GRANT` â†’ `execution_not_granted`, path deny shared with A06. Injection-parse negatives SOURCE_WIRED (`AgentParseToolCalls`) / HTTP NOT_RUN. MET=0 |
| A08 | Lifecycle safety (freed IDE / cancel / leaks) | **OPEN** | No tip receipt closing gate |
| A09 | Fatal crash + data loss recovery | **OPEN** | No tip receipt closing gate |
| A10 | CMake-omit legitimacy | **OPEN** | `WIN32IDE_FULL_SOURCE_AUDIT_001` inventories omit/orphan; adjudication incomplete â†’ PERFECT=0 |
| A11 | K2 full product generation | **BLOCKED** | `K2_FULL_PRODUCT_GEN_002` BLOCKED_OOM on CURRENT (`WIN32IDE_FULL_SOURCE_AUDIT_001` MATRIX A26); GENERATED_TOKENS=0 |
| A12 | Source inventory 100% path/hash/class + win32app reconcile | **OPEN** | Audit landed inventory counts; PERFECT=0 / OPEN list non-empty |
| A13 | Target attribution (every selected TU + map; orphans classified) | **OPEN** | CMake net/orphan counts exist; full object/link-map attribution not MET |
| A14 | Findings adjudication (no unresolved P0/P1) | **OPEN** | S-001 RUNTIME_REACHED (not MET); S-002/S-003/S-004 tip-linked SOURCE_WIRED; S-005 SOURCE_WIRED RELINK_REQUIRED (`SHELLLAYOUT_PHASE5_001`); FEATURE_FICTION GateFiction GATED (`COMMAND_HANDLERS_FICTION_GATE_001`) |
| A15 | Promotion authority | **HELD** | `PROMOTE=0` Â· `PROMOTE_READY_CONJUNCTION_001` Â· never manually forced |

## S-001â€“S-005 Static findings (local presence)

| ID | Finding | Status | Cite |
|----|---------|--------|------|
| S-001 | ToolActionStatus synthetic terminal + FinishedAction(0) | **RUNTIME_PARTIAL** | E2E_002 4-case on tip `6832F439â€¦`; Admit/VSCodeUI/hookToolResult SOURCE_WIRED not tip-absorbed; MET=0; cites `TOOL_ACTION_STATUS_E2E_002` + `TOOL_ACTION_STATUS_RUNTIME_001` |
| S-002 | Swarm 4 fixed prompts / maxParallel=4 (not 1â€“16 configurable) | **SOURCE_WIRED** | `SWARM_MODEL_ORCH_001` N=1..16 + maxParallelâ‰¤N; tip-linked `TIP_ABSORB_SWARM_002`; `SWARM_16_RUNTIME_001` CMD=4111 WM_COMMAND â€” GUI exit=2 (no window station) + headless no orch expose â†’ **INVOKED=0 / LINKEDâ‰ INVOKED**; RUNTIME_REACHED not earned |
| S-003 | Swarm model enum: one-dir `*.gguf` only | **SOURCE_WIRED** | `SWARM_MODEL_ORCH_001` â€” multi-root GGUF + `/api/tags`; **HttpTags LINKED** (`appendLocalOllamaHttpTags` in map via `TIP_ABSORB_SWARM_002`); product swarm GUI RUNTIME NOT_RUN |
| S-004 | AgenticComposerUX static callbacks / default-model / MessageBox | **SOURCE_WIRED** | Real model bind (`AGENTIC_COMPOSER_UX_001`); tip absorb via `TIP_ABSORB_RELINK_001` â†’ `6832F439â€¦`; `AGENTIC_COMPOSER_RUNTIME_001` INVOKED_SURFACE (`HandleAgenticComposerUX` RVA `0x5C0C40`) â€” **RUNTIME_REACHED NOT_RUN** |
| S-005 | ShellLayout phase 5 terminal stub | **SOURCE_WIRED** | `SHELLLAYOUT_PHASE5_001` chrome â†’ `getPowerShellPanel` + GateTerminal; ConPTY stream owner **SOURCE_WIRED** (`CONPTY_STREAM_OWNER_001` â†’ `Win32TerminalManager`/CreatePseudoConsole); **RELINK_REQUIRED** (tip `6832F439â€¦` stays); RUNTIME_REACHED=NOT_RUN |

## G01â€“G20 Agentic functionality

| ID | Feature | Status | Cite / note |
|----|---------|--------|-------------|
| G01 | Ask mode | **SOURCE** | INVOKED_SURFACE tip map `onAgenticModeAsk` RVA `0x5A8850` (`AGENTIC_COMPOSER_RUNTIME_001`); E2E/RUNTIME NOT_RUN â€” not MET |
| G02 | Agent mode E2E tool loop | **SOURCE** | INVOKED_SURFACE tip map `onAgenticModeAgent` RVA `0x5A8840` (`AGENTIC_COMPOSER_RUNTIME_001`); `AGENT_LIFECYCLE_TIP_001` headless tool steps â‰  AgentRunLoop; E2E NOT_RUN â€” not MET |
| G03 | Plan mode | **SOURCE** | INVOKED_SURFACE tip map `onAgenticModePlan` RVA `0x5A8870` (`AGENTIC_COMPOSER_RUNTIME_001`); E2E/RUNTIME NOT_RUN â€” not MET |
| G04 | Debug mode | **OPEN** | **NOT_INVOKED** on tip â€” no `AgenticMode::Debug` (`agentic_mode_switcher.hpp` / `AGENTIC_COMPOSER_RUNTIME_001`) |
| G05 | Auto mode routing | **OPEN** | **NOT_INVOKED** on tip â€” no `AgenticMode::Auto` (`agentic_mode_switcher.hpp` / `AGENTIC_COMPOSER_RUNTIME_001`) |
| G06 | Model registry live list | **SOURCE** | Swarm/Ollama dir scan wiring exists (S-003); live registry E2E OPEN |
| G07 | Model ensemble 1â€“16 | **SOURCE_WIRED** | S-002/S-003 tip-linked; `SWARM_16_RUNTIME_001` INVOKED=NOT_RUN on `6832F439â€¦` (GUI createWindow exit=2; headless distributed swarm â‰  orch; `/api/subagent` nativeHexMag=false; TIP_REBUILD=NO); Ollama `SWARM_TIP_16_HI_AUDIT_001` 16/16 â‰  tip EXE RUNTIME_PASS â€” **G07 not MET** |
| G08 | Execution topology | **SOURCE_WIRED** | Orch `maxParallel`/`sequential` SOURCE_WIRED+LINKED (SubAgent.cpp); tip runtime topology NOT_OBSERVED (`SWARM_16_RUNTIME_001` INVOKED=0) â€” not MET |
| G09 | Concurrency fairness | **OPEN** | No tip receipt |
| G10 | Stop/cancel | **OPEN** | `SWARM_16_RUNTIME_001` cancel NOT_ATTEMPTED (no live tip swarm); SubAgent cancelAll on shutdown = SOURCE only â€” not MET |
| G11 | Pause/resume | **OPEN** | No tip receipt |
| G12 | Checkpoint/rollback | **OPEN** | `AGENT_LIFECYCLE_TIP_001` write_file restore â‰  CheckpointManager product API â€” NOT_RUN |
| G13 | Multi-workspace | **OPEN** | No tip receipt |
| G14 | Tool dispatch schemaâ†’callable | **RUNTIME_PARTIAL** | Tip `/api/tool` list_directory+read_motd callable (`TOOL_ACTION_STATUS_E2E_002`); full schema matrix not MET |
| G15 | Tool errors truthful | **RUNTIME_PARTIAL** | Tip `/api/tool` file_not_found propagates (`TOOL_ACTION_STATUS_E2E_002`); synthetic consumer reject tip-absorb pending RELINK |
| G16 | Headless `/api/tool` | **MET** | Tip `6832F439â€¦` `HEADLESS_API_TOOL_TIP_001` (MOTD+list + auth NEG). Additive lifecycle breadth: `AGENT_LIFECYCLE_TIP_001` write/exec/diff/accept/rollback+cancel on port 19891 (`execute_command` PASS with `RAWRXD_IDE_EXEC_GRANT=1`). PROMOTE=0 |
| G17 | Extension host | **SOURCE** | FeatureManifest / omit gates; runtime OPEN |
| G18 | Browser/OS authority | **OPEN** | No tip receipt |
| G19 | MOTD gate | **SOURCE** | Policy/MOTD rules present; product session E2E OPEN |
| G20 | Agent metrics | **OPEN** | Composer metrics cmds SOURCE; product metrics seal OPEN |

## U01â€“U18 Polished IDE UI

| ID | Feature | Status | Cite / note |
|----|---------|--------|-------------|
| U01 | Composer modes/chooser | **SOURCE** | Ask/Plan/Agent INVOKED_SURFACE on tip (`AGENTIC_COMPOSER_RUNTIME_001`); Debug/Auto NOT_INVOKED; S-004 SOURCE_WIRED; full UI/RUNTIME MET denied |
| U02 | Chain-of-models picker 1â€“16 | **SOURCE_WIRED** | S-002/S-003 tip-linked; `SWARM_16_RUNTIME_001` tip GUI picker/swarm **NOT_RUN** (createWindow_FAILED) â€” RUNTIME_REACHED not earned; picker UI E2E not MET |
| U03 | Real progress timeline | **OPEN** | No tip receipt |
| U04 | Review changes Accept/Reject | **SOURCE** | Composer approve/reject cmds exist; E2E OPEN |
| U05 | Stop control | **OPEN** | No tip receipt |
| U06 | Background terminal / ConPTY | **SOURCE_WIRED** | Chrome: `SHELLLAYOUT_PHASE5_001`/`getPowerShellPanel`. Stream owner: `CONPTY_STREAM_OWNER_001` â†’ `Win32TerminalManager` CreatePseudoConsole (panel/`tab.manager`); GateConPtyStream fail-closed; RELINK_REQUIRED; RUNTIME NOT_RUN; â‰  PASS |
| U07 | Dock layout resize/DPI | **SOURCE** | ShellLayout phases 0â€“5 SOURCE_WIRED; full docking E2E OPEN |
| U08 | Audit/review tab | **OPEN** | No tip receipt |
| U09 | Session/history durable | **OPEN** | No tip receipt |
| U10 | Context management | **OPEN** | No tip receipt |
| U11 | Explorer / quick open | **OPEN** | No tip receipt |
| U12 | Editor core | **OPEN** | No tip receipt as closure |
| U13 | LSP | **OPEN** | No tip receipt |
| U14 | Debugger UI | **OPEN** | No tip receipt |
| U15 | Accessibility | **OPEN** | No tip receipt |
| U16 | Visual consistency | **OPEN** | P2; no tip receipt |
| U17 | Responsive UX | **OPEN** | P2; no tip receipt |
| U18 | Notifications (no invented toasts) | **RUNTIME_PARTIAL** | Tied to A05/`TOOL_ACTION_STATUS_E2E_002` (VSCodeUI FinishedAction invent gated in source; tip absorb pending) |

## I01â€“I12 Inference and runtime

| ID | Feature | Status | Cite / note |
|----|---------|--------|-------------|
| I01 | GGUF families token production | **MET** | TinyLlama tetrad + gemma3 MULTI_FAMILY_005 on tip `6832F439â€¦` (narrow families only; not all supported arches) |
| I02 | Quantization oracle gates | **OPEN** | No oracle seal on tip |
| I03 | CPU/GPU fallback observable | **OPEN** | Inference SPLIT HOLD (`PROMOTE_READY` / audit) |
| I04 | Vulkan GEMV | **OPEN** | No tip repair seal |
| I05 | Vulkan synchronization | **OPEN** | No tip seal |
| I06 | Multi-GPU placement | **OPEN** | No tip seal |
| I07 | Long context vs KV | **OPEN** | No tip seal |
| I08 | MoE scheduler | **OPEN** | No tip seal |
| I09 | Memory protection / admission | **BLOCKED** | K2 OOM path documents refusal/fail; full graceful product admission not MET |
| I10 | Model switching | **OPEN** | No tip seal |
| I11 | Concurrency 1..16 agents | **OPEN** | No tip seal |
| I12 | Performance seals per-model TPS | **MET** | `TOKEN64_PRODUCT_RUN_005` TPS_PRODUCT_SEAL=1 on tip (TinyLlama 64); not universal per-model matrix |

## Top OPEN (priority)

1. **A02** â€” Camellia RFC self_test BLOCKED_DOCUMENTED (`self_test=-8`)
2. **G07 / swarm tip RUNTIME** â€” `SWARM_16_RUNTIME_001` INVOKED=NOT_RUN (`6832F439â€¦`; GUI window-station exit=2 + HEADLESS_NO_ORCH_EXPOSE; TIP_REBUILD=NO); Ollama â‰  tip EXE RUNTIME; classify `SWARM_16_THINKING_CLASSIFY_001` â‰  G07 MET |
3. **S-005 / U06 RELINK** â€” chrome + stream SOURCE_WIRED (`SHELLLAYOUT_PHASE5_001` + `CONPTY_STREAM_OWNER_001`); tip absorb + RUNTIME still OPEN
4. **A04 / G02** â€” agent bridge GUI + AgentRunLoop E2E on tip SHA (G16 MET: `HEADLESS_API_TOOL_TIP_001` + lifecycle `AGENT_LIFECYCLE_TIP_001`; G02=SOURCE INVOKED_SURFACE via `AGENTIC_COMPOSER_RUNTIME_001`, AgentRunLoop E2E still not MET)
5. **A11 / I09** â€” K2 full gen BLOCKED_OOM
6. **A15** â€” PROMOTE remains HELD (`PROMOTE=0`)

## Explicit non-claims

```
PERFECT=0 (WIN32IDE_FULL_SOURCE_AUDIT_001)
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
G07_MET=0 (SWARM_16_RUNTIME_001 INVOKED=0 RUNTIME_PASS=0 on tip 6832F439; Ollama HIâ‰ tip orch)
SWARM_16_THINKING_CLASSIFY_001 classify contract additive (thinking-only â‰  PASS)
I01/I12 MET â‰  full inference matrix MET
A01 MET on 6832F439 â‰  PROMOTE
A03 MET on 6832F439 â‰  PROMOTE
A06 RUNTIME_REACHED deny on 6832F439 (SAFE_WRITE_APPROVAL_TIP_001) + SOURCE_WIRED atomic/preview/rollback (SAFE_WRITE_ATOMIC_001 RELINK_REQUIRED) â‰  MET â‰  PROMOTE
A07 RUNTIME_REACHED on 6832F439 (SAFE_WRITE_APPROVAL_TIP_001) â‰  MET â‰  PROMOTE
G16 MET on 6832F439 â‰  PROMOTE
Historical C4FC9AE9 / 866E9D1B seals untouched
WIN32IDE_BINARY_PROVENANCE_002 HISTORICAL (C4FC9AE9 FAIL_CLOSED)
WIN32IDE_BINARY_PROVENANCE_003 A01=MET for 6832F439 only
```

