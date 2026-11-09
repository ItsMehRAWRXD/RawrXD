# RawrXD / Deep2 IDE completion ledger

As-of: 2026-11-02 America/New_York  
Control state: `PROMOTE=0`, `TIP_CLIMB=HOLD`, `CERTIFIED=0`  
Scope: Phase 1 reconciliation and Phase 2/3/4 completion queue. No frozen binary was modified.

## Authority and workspace reconciliation

| Item | Observed state |
|---|---|
| Primary workspace | `F:\rawrxd` |
| Primary HEAD | `2fcba4e60bcb8d5507134c2153c9245966de8602` |
| Primary branch | `fix/deep2-multimodel-safety-20261025` |
| Primary tree | Dirty; tracked Deep2/CMake/ledger changes and numerous untracked artifacts |
| Agentic workspace | `G:\~dev\rawrxd` |
| Agentic HEAD | `273924f9f4b0d75ed770559da448164ec632ce00` |
| Agentic branch | `feature/ide-agentic-product-path-20261026` |
| Agentic tree | Dirty; dump-repair edits and untracked evidence/candidate material |
| Frozen authority | `G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe` |
| Frozen SHA-256 | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Frozen authority status | Present; hash matches the declared `748B210A` prefix |

### Source census

The reproducible census below counts source extensions while excluding build trees, VCS metadata, node modules, archive/backup trees, and evidence trees. It is an inventory baseline, not a claim that every file is part of the product graph.

| Workspace | cpp | c | h | hpp | asm | inc | total |
|---|---:|---:|---:|---:|---:|---:|---:|
| `F:\rawrxd` | 3323 | 286 | 984 | 1637 | 230 | 11 | **6471** |
| `G:\~dev\rawrxd` | 19043 | 915 | 6641 | 5780 | 6751 | 195 | **39325** |

The primary CMake file contains 134 `add_executable` declarations and 16 `add_library` declarations. The native IDE target is `RawrXD-Win32IDE` around `F:\rawrxd\CMakeLists.txt:1507`; a separate native target `RawrXD-Win32IDE-Native` is declared around line 3763. This target multiplicity is a build-authority risk and must be resolved before promotion.

## Feature matrix

Classification is evidence-backed; no source presence is treated as runtime verification.

| Feature | Classification | Source/call-site anchors | Evidence / next proof |
|---|---|---|---|
| Native Win32 shell, menus, docking | IMPLEMENTED_UNVERIFIED | `src/win32app/Win32IDE.cpp`, `Win32IDE_Commands.cpp`, `Win32IDE_Sidebar.cpp` | `evidence/WIN32IDE_CONTINUOUS_LOOP_001`; relinked-candidate HWND receipt required |
| Editor/file operations/tabs | IMPLEMENTED_UNVERIFIED | `Win32IDE_FileOps.cpp`, `Win32IDE.cpp` | UI E2E receipt required |
| Ghost Text/completion | PARTIAL | `real_time_completion_engine.cpp`, `Win32IDE_CopilotIntegration.cpp` | `AUDIT_002_GHOSTTEXT_DRAIN_RECONCILED_001/ASSESSMENT.md`; runtime not run |
| Local GGUF discovery/loading | IMPLEMENTED_UNVERIFIED | `gguf_loader.cpp`, `streaming_gguf_loader.cpp`, model router sources | real local-model selection/stream receipt required |
| Ollama discovery | IMPLEMENTED_UNVERIFIED | `universal_model_router.cpp`, `cloud_api_client.cpp` | offline/local-only discovery test required |
| Model selection/session switching | IMPLEMENTED_UNVERIFIED | `model_router_widget.cpp`, `model_router_adapter.cpp` | `WIN32IDE_CONTINUOUS_LOOP_001/NEMOTRON_MODEL_SELECTION.md`; full switch/cancel proof required |
| Streaming/cancellation | PARTIAL | `CopilotStreaming.cpp`, inference engine sources | real-model cancellation receipt required |
| Terminal/PowerShell | IMPLEMENTED_UNVERIFIED | `Win32TerminalManager.cpp`, `Win32IDE_PowerShell*.cpp` | GUI interaction receipt required |
| Compiler/diagnostics | IMPLEMENTED_UNVERIFIED | `Win32IDE_Debugger.cpp`, `Diagnostics.cpp`, compiler target | build/test/diagnostic receipt required |
| Debugger | IMPLEMENTED_UNVERIFIED | `Win32IDE_Debugger.cpp` | debugger launch/breakpoint/watch receipt required |
| Agent session/run loop | PARTIAL | `Win32IDE_AgenticBridge.cpp`, `Win32IDE_AgentCommands.cpp`, `deep2_agentic_loop` target | `AGENT_E2E_001/002` are not certified; real tool-result receipt required |
| File-edit/build/repair tools | PARTIAL | agent bridge and `src/agentic/*` | exact file-change + build receipt required |
| Swarm 1–16 model orchestration | IMPLEMENTED_UNVERIFIED | agentic/deep2 orchestration sources | matrix and cancellation/idle-stop proof required |
| Workspace restoration/settings | IMPLEMENTED_UNVERIFIED | IDE main window/settings sources | restart/restore receipt required |
| REAP controls | IMPLEMENTED_UNVERIFIED | REAP/deep2 integration sources | IDE control integration receipt required |
| Dual-GPU / K2 parity | BLOCKED_BY_AUTH | Deep2 GPU/K2 sources and parity harnesses | host-stability and authorization gates required |
| Extension runtime | STUB_OR_FALLBACK | extension-host integration | `AUDIT_002.../ASSESSMENT.md`: `EXTENSION_RUNTIME=FAIL`, PASS=0, FAIL=5, BLOCKED=1 |

Completed feature count in this ledger: **0 runtime-verified product features**. Implemented/unverified or partial source paths are not promoted to verified. Remaining: **16** non-runtime-verified rows, including **1 blocked by authorization** and **1 failing/stub-or-fallback path**.

## Audit and certification state

- `AUDIT_002_GHOSTTEXT_DRAIN_RECONCILED_001`: GhostText inventory closed (`GHOSTTEXT_OPENISH=0`), but runtime not run.
- `AUDIT_002_DRAIN`: 261 OPENISH orphan TUs remain; next gate is `AUDIT_002_OPENISH_OTHER_DRAIN`.
- Extension runtime: failed on candidate `73368`; missing ExtensionHost child is the named controlling blocker.
- `PROMOTE=0`, `TIP_CLIMB=HOLD`, `CERTIFIED=0`; do not inherit PASS from another binary.
- No K2 host-RAM requirement was found in the reconciled records sufficient to authorize execution; treat K2 host-RAM sizing as **outstanding** until the authority owner supplies the requirement and approval.

## P0/P1/P2 blockers

### P0

1. No current candidate is certified or authorized for promotion; frozen tip must remain untouched.
2. Host crash-dump/stability gate is unresolved; heavy runtime tests remain held.
3. ExtensionHost runtime is failing, so GhostText end-to-end cannot be certified.

### P1

1. Reconcile `RawrXD-Win32IDE` versus `RawrXD-Win32IDE-Native` as the single build authority.
2. Produce real GUI receipts for editor, model, terminal, compiler/debugger, agent, and restart flows.
3. Resolve K2 host/GPU token parity and GPU numerical parity before performance claims.
4. Drain the 261 OPENISH audit residuals without inventing PASS.

### P2

1. Expand model-family coverage, dual-GPU validation, REAP residency determinism, and TPS benchmarks after correctness.
2. Package/install/first-run verification.

## Exact next authorized action

Source-only: diagnose the ExtensionHost child launch path against candidate `73368`, identify the exact source/function and minimal fix, and write a non-runtime repair plan. Do not relink the frozen tip, run heavy inference, absorb candidates, change `PROMOTE`, or perform R28 APPLY. After explicit authorization and host gate clearance, run the smallest real GUI smoke on a newly hashed candidate and record receipts.

