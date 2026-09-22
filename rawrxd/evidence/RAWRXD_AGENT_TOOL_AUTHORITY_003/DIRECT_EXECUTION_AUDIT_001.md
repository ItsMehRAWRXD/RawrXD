# RAWRXD_DIRECT_EXECUTION_AUDIT_001

Audit Date: 2026-09-19
Auditor: AgentToolAuthority / Batch-2 continuation
Scope: rawrxd/src/**/*.cpp + src/*.cpp
Pattern: _popen(|system(|CreateProcessA(|CreateProcess(|CreateProcessAsUserA(

---

## Executive Summary

| Bucket | Files | Call Sites (est.) | Priority |
|---|---|---|---|
| AGENT_ACTION | 18 | ~120 | P0 — must migrate through AgentToolRegistry::invoke() |
| PRODUCT_INFRASTRUCTURE | 7 | ~35 | P1 — allowed direct execution, document rationale |
| DEAD_LEGACY | 3 | ~15 | P2 — remove or fail-closed |
| UNCLASSIFIED | ~12 | ~35 | P1 — needs manual review |
| **TOTAL** | **~40** | **~205** | |

---

## AGENT_ACTION — Must Migrate Through AgentToolRegistry

These files contain direct process/shell execution that an autonomous agent can reach. Every call site must eventually cross `AgentToolRegistry::invoke()`.

| # | File | Call Type | Count | Migration Status |
|---|---|---|---|---|
| 1 | `rawrxd/src/deep2/HeadlessIDE_AutonomousWorkflowMode.cpp` | `_popen` | 1 | **NOT MIGRATED** — `toolRunShell` uses direct `_popen`. Comment claims dispatch crosses registry, but provider still uses direct call. |
| 2 | `rawrxd/src/ceo/AutonomousBuildLoop.cpp` | `_popen` | 1 | **NOT MIGRATED** — CEO build loop `RunCommand` uses `_popen` directly. |
| 3 | `rawrxd/src/core/feature_handlers.cpp` | `_popen`, `CreateProcessA` | ~12 | **PARTIAL** — `handleTerminalNew` (CreateProcessA), `handleREDecisionTree`/`handleRESSALift` (`runExternalTool` → `_popen`), `handleVoiceTranscribe`, `handleVoiceSpeak`, `handleAIBackend`, `handleAgentExecute` (agent instruction path), `handleGitStatus`, `handleGitPush`, `handleGitPull`, `handleGitDiff`. |
| 4 | `rawrxd/src/core/auto_feature_registry.cpp` | `_popen`, `system`, `CreateProcessA` | ~15 | **NOT MIGRATED** — Self-test gate, findstr scans, cmake build, git status/branch, direct `system(cmd)`. Used during feature registration discovery. Agent can trigger registration scan. |
| 5 | `rawrxd/src/core/SovereignAutoLoop.cpp` | `_popen` | 1 | **NOT MIGRATED** — Autonomous loop shell execution. |
| 6 | `rawrxd/src/core/SovereignSEG.cpp` | `_popen` | 1 | **NOT MIGRATED** — SEG (Self-Executing Graph) shell dispatch. |
| 7 | `rawrxd/src/core/SovereignSelfBuildLoop.cpp` | `CreateProcessA` | 2 | **NOT MIGRATED** — `SovereignBuild_Run` directly spawns `build_moe_dll.bat` and `build_ide.bat`. |
| 8 | `rawrxd/src/core/SovereignHypervisor.cpp` | `CreateProcess` | 1 | **NOT MIGRATED** — VM launcher. Agent can trigger hypervisor operations. |
| 9 | `rawrxd/src/core/autonomous_debugger.cpp` | `system` | 1 | **NOT MIGRATED** — Debugger command execution. Agent can trigger debug sessions. |
| 10 | `rawrxd/src/core/backup_manager.cpp` | `system` | 1 | **NOT MIGRATED** — Backup command execution. |
| 11 | `rawrxd/src/core/production_release.cpp` | `system`, `CreateProcessA` | 2 | **NOT MIGRATED** — Release packaging and post-build steps. |
| 12 | `rawrxd/src/core/model_training_pipeline.cpp` | `_popen`, `CreateProcessA` | 3 | **NOT MIGRATED** — Training pipeline subprocesses. |
| 13 | `rawrxd/src/core/ssot_handlers.cpp` | `_popen`, `CreateProcessA` | ~35 | **NOT MIGRATED** — Largest single file hit. SSOT command handlers for build, git, cmake, taskkill, network scan (arp), LSP server launch, and more. Agent reaches these via `!` commands. |
| 14 | `rawrxd/src/core/ssot_handlers_ext.cpp` | `_popen`, `CreateProcessA` | ~25 | **NOT MIGRATED** — Extended SSOT handlers: clang-tidy, clangd, powercfg, git operations, cmd.exe spawn, devenv/windbg launch, RE tools. |
| 15 | `rawrxd/src/core/ssot_handlers_ext_dedicated.cpp` | `_popen`, `CreateProcessA` | ~10 | **NOT MIGRATED** — Dedicated SSOT handlers: terminal spawn, build, debug launch, cmake, git. |
| 16 | `rawrxd/src/core/js_extension_host.cpp` | `CreateProcessA`, `ShellExecuteA` | 2 | **NOT MIGRATED** — Extension host process spawn and URI open. |
| 17 | `rawrxd/src/core/shadow_page_detour.cpp` | `CreateProcessA` | 1 | **NOT MIGRATED** — Agentic assembler `ml64.exe` spawn. |
| 18 | `rawrxd/src/core/swarm_worker.cpp` | `CreateProcessA` | 1 | **NOT MIGRATED** — Swarm task executor. |

**AGENT_ACTION total call sites: ~120**

---

## PRODUCT_INFRASTRUCTURE — Allowed Direct Execution

These files create processes as part of core infrastructure. They are allowed direct execution **only if** they are invoked through `AgentToolRegistry::invoke()` as the canonical provider implementation, or if they are low-level OS services not reachable by agent logic.

| # | File | Call Type | Count | Rationale |
|---|---|---|---|---|
| 1 | `rawrxd/src/core/execution_governor.cpp` | `CreateProcessA` | 1 | `TerminalWatchdog::ExecuteSafe` — non-blocking execution governor with PeekNamedPipe polling. This is a **canonical provider** that AgentToolRegistry should delegate to. Current direct call is infrastructure, but the boundary must be registry → governor, not caller → governor. |
| 2 | `rawrxd/src/core/task_system.hpp` | `CreateProcessA` | 1 | `TaskRunner::createProcess` — generic task execution system. Same rationale: should only be reached via registry. |
| 3 | `rawrxd/src/core/sandbox_integration.cpp` | `CreateProcessA`, `CreateProcessAsUserA` | 2 | Sandboxed process launcher with restricted token. Low-level security infrastructure. Should be registry-backed. |
| 4 | `rawrxd/src/core/native_debugger_engine.cpp` | `CreateProcess` (DbgEng) | 1 | Native debugger engine via DbgEng `CreateProcessAndAttach`. IDE infrastructure, not agent-reachable in normal workflow. |
| 5 | `rawrxd/src/core/unified_inference_engine.c` | `CreateProcessA` | 1 | Inference engine subprocess launcher. Low-level GPU/CPU inference infrastructure. |
| 6 | `rawrxd/src/core/dual_engine_system.cpp` | `_popen`, `system` | 4 | `nvidia-smi` temperature query and system commands. Hardware monitoring infrastructure. Agent does not directly reach temperature polling; it's a background health check. |
| 7 | `rawrxd/src/reverse_engineering/RawrCompiler.hpp` | `CreateProcessA` | 1 | Compiler subprocess for reverse engineering tools. Part of RE toolchain infrastructure. |

**PRODUCT_INFRASTRUCTURE total call sites: ~35**

---

## DEAD_LEGACY — Remove or Fail-Closed

| # | File | Call Type | Count | Status |
|---|---|---|---|---|
| 1 | `rawrxd/src/core/ToolRegistry.cpp` | `CreateProcessA` | 1 | **FAIL-CLOSED** — Compile-time `#error` guard `RAWRXD_LEGACY_TOOL_REGISTRY_ALLOWED` already in place. Excluded from product build. |
| 2 | `rawrxd/src/core/rawrxd_core.h` | `_popen` | 1 | **STALE** — C-style `rxd_tool_term_exec` and `rxd_tool_git_cmd`. Superseded by AgentToolRegistry. Needs `#error` guard or removal. |
| 3 | `rawrxd/src/core/test_e2e_splitter_decoder.cpp` | `CreateProcessA` | 1 | **TEST-ONLY** — E2E test harness. Not part of product runtime. |

**DEAD_LEGACY total call sites: ~15**

---

## UNCLASSIFIED — Needs Manual Review

| # | File | Call Type | Count | Notes |
|---|---|---|---|---|
| 1 | `rawrxd/src/core/rawrxd_swarm.h` | `system` | 1 | Header-only `system(cmd)` in swarm coordinator. Verify if still included in product build. |
| 2 | `src/rawr_agent_audit_driver.cpp` | `_popen` | 1 | Audit driver in top-level `src/`. Verify if this is test tooling or product surface. |
| 3 | `src/rawr_agent_dispatch.cpp` | `_popen` | 2 | Agent dispatch in top-level `src/`. Verify if active or superseded by `AgentToolRegistry`. |
| 4 | `rawrxd/src/reverse_engineering/pe_tools/re_tools.cpp` | `system` | 1 | RE tool subprocess. Verify if agent-reachable. |
| 5-12 | Various `.cpp` files with 1-2 hits each | mixed | ~30 | Files with isolated calls not yet read in detail. Queue for second-pass classification. |

**UNCLASSIFIED total call sites: ~35**

---

## Migration Priority Queue

### P0 — Migrate before next certification
1. `HeadlessIDE_AutonomousWorkflowMode.cpp::toolRunShell` — Headless surface provider
2. `AutonomousBuildLoop.cpp::RunCommand` — CEO build loop
3. `feature_handlers.cpp` — Agent-reachable handlers (`handleAgentExecute`, `handleTerminalNew`, `handleVoice*`, `handleRE*`, `handleGit*`)
4. `ssot_handlers.cpp` / `ssot_handlers_ext.cpp` / `ssot_handlers_ext_dedicated.cpp` — SSOT command surface (largest volume)
5. `Sovereign*.cpp` files — Sovereign autonomous loop, SEG, self-build, hypervisor

### P1 — Infrastructure hardening
6. `execution_governor.cpp` — Ensure registry → governor boundary
7. `task_system.hpp` — Ensure registry → task_system boundary
8. `sandbox_integration.cpp` — Ensure registry → sandbox boundary
9. `dual_engine_system.cpp` — Monitor-only; verify agent cannot reach temperature commands

### P2 — Cleanup
10. `rawrxd_core.h` — Add `#error` guard or remove stale C-style tool functions
11. `ToolRegistry.cpp` — Already fail-closed; confirm excluded from build
12. `test_e2e_splitter_decoder.cpp` — Confirm test-only exclusion

---

## Invariants

```
AGENT_ACTION_MIGRATED=0
AGENT_ACTION_REMAINING=~120
PRODUCT_INFRASTRUCTURE_DOCUMENTED=~35
DEAD_LEGACY_CLOSED=~15
UNCLASSIFIED=~35

DIRECT_AGENT_BYPASSES=AGENT_ACTION_REMAINING + UNCLASSIFIED_AGENT_ACTION
TARGET_DIRECT_AGENT_BYPASSES=0
```

## Result

```
RAWRXD_DIRECT_EXECUTION_AUDIT_001
STATUS=PARTIAL
AGENT_ACTION=~120
PRODUCT_INFRASTRUCTURE=~35
DEAD_LEGACY=~15
UNCLASSIFIED=~35
TOTAL_ESTIMATED=~205
NEXT_ACTION=MIGRATE_P0_AGENT_ACTION_FILES
CERTIFICATION_STATUS=PENDING
```
