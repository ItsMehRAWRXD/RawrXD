# RawrXD Win32IDE — Product Closure Matrix (October 28, 2026)

**Authority:** user-reported local product tip `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F`  
**Disposition:** `PROMOTE=0`, `CERTIFIED=0`, `TIP_CLIMB=HOLD`  
**Evidence caution:** This document is a prioritized verification/implementation backlog. It is NOT proof that any local binary has passed the tests below. The October 27 connected GitHub branch is not established as the provenance of the local EXE.

## Reported completions (do not transfer to later hashes)

- Native Win32IDE link with symbol batches 001–022 resolved or explicitly omitted.
- Blocker matrix B01–B16 closed in its stated scope.
- AnnotationOverlay source bindings for agent bridge and screen rectangle.
- Camellia ASM auth non-synthetic link and reported runtime-auth smoke; gold-link ABI cleared.
- Watchdog ASM restored and MagBuf CRC join cleared.
- Camellia HMAC product smoke reached and absorbed into the product tip.
- Latest user update reports LIVE_TETRAD, TOKEN64 (`TPS_PRODUCT_SEAL=1`), and MULTI_FAMILY on `866E9D1B…` as closed.
- ShellLayout phases 0–4 reportedly pass; phase 5 remains explicitly unimplemented.
- AgenticBridge, Neural, ExtensionHost, Logpoint, Sidebar and headless routes contain source wiring/fail-closed gating; runtime breadth not established.
- Prior Deep2 CPU/GPU, GGUF, Ollama, agentic-loop, bridge, and IDE-smoke passes are historical and should be rerun against the product tip as applicable.

## Confirmed GitHub-branch static findings requiring reconciliation

| ID | Priority | Branch path | Source evidence | Required closure |
|---|---|---|---|---|
| S-001 | P0 candidate | `src/win32app/Win32IDE_ToolActionStatus.cpp` GateStub | Was FinishedAction(0) synthetic; now GateStub SYNTHETIC=1 DEMO — RUNTIME_REACHED on tip 6832F439 via `TOOL_ACTION_STATUS_RUNTIME_001`; MET=0 until real process-exit receipts | Show real tool receipts or label strictly DEMO; prevent synthetic success in shipping run history |
| S-002 | P1 | `src/win32app/Win32IDE_SubAgent.cpp:268-314` | Swarm path constructs 4 fixed analysis prompts with `maxParallel=4`, not a configurable 16-model selection | Configurable 1–16 model tasks, parallel/sequential/chain scheduler and actual runtime verification |
| S-003 | P1 | `src/win32app/Win32IDE_SwarmModelSelector.cpp:42-83` | Enumeration only scans one directory for `*.gguf` | Integrate Ollama tags/manifests plus deep GGUF discovery and canonical IDs |
| S-004 | P1 | `src/win32app/Win32IDE_AgenticComposerUX.cpp:17-63` | Static callbacks capture IDE; `default-model` string; shows message box | Real active-model binding, full composer UI, instance lifecycle/shutdown tests |
| S-005 | P1 | `src/win32app/Win32IDE_ShellLayout.cpp` PHASE=5 + `Win32TerminalManager` | Chrome SOURCE_WIRED (`SHELLLAYOUT_PHASE5_001`); stream SOURCE_WIRED (`CONPTY_STREAM_OWNER_001` CreatePseudoConsole); RELINK_REQUIRED; RUNTIME NOT_RUN | Tip absorb + RUNTIME_REACHED + live ConPTY stream/resize/DPI/focus tests |

These findings are from `feature/ide-agentic-product-path-20261026` commit `219b0e5694e565575728faf6c820d3f76cfb8006`. Their presence in the local product build is unproven until source-provenance reconciliation.

## Release-blocking gates

Legend: `OPEN` = not demonstrated as closed; `HELD` = deliberately blocked; `HISTORICAL` = older source or binary pass, must revalidate as appropriate; `SOURCE` = wiring visible, behavior not yet established.

| ID | Priority | Gate / subsystem | Evidence required | Current disposition |
|---|---|---|---|---|
| A01 | P0 | Binary provenance | Exact EXE hash, CMake source snapshot/commit, build logs and MAP/PDB linkage | MET — PROVENANCE_003 on 6832F439 (PROVENANCE_002 HISTORICAL) |
| A02 | P0 | Camellia `self_test=-8` | Root cause, correct RFC vectors/schedule, fixed non-synthetic self-test | OPEN |
| A03 | P0 | Post-fix tip seal | Rerun LIVE_TETRAD + TOKEN64 + MULTI_FAMILY on each new EXE SHA | HELD for next SHA |
| A04 | P0 | Agent bridge and Watchdog | Real product GUI + headless runtime tests on same SHA | OPEN |
| A05 | P0 | No fabricated tool success | Execution event IDs tied to real exit codes, stdout/stderr, cancellation | RUNTIME_REACHED on 6832F439 (GateStub ODS; MET=0) |
| A06 | P0 | Safe file writes | Atomic writes, previews, rollback, deny outside workspace by default, backups | RUNTIME_REACHED — deny earned on 6832F439 (`SAFE_WRITE_APPROVAL_TIP_001`, untouched); atomic/preview/rollback SOURCE_WIRED (`SAFE_WRITE_ATOMIC_001`) RELINK_REQUIRED RUNTIME NOT_RUN; MET=0 |
| A07 | P0 | Tool approval and isolation | Path, shell and network policy enforcement; malicious prompt injection negative controls | RUNTIME_REACHED — auth/origin/exec/path negatives on 6832F439 (`SAFE_WRITE_APPROVAL_TIP_001`); injection HTTP NOT_RUN; MET=0 |
| A08 | P0 | Lifecycle safety | No callback on freed IDE; shutdown cancels threads and subprocesses; leak checks | OPEN |
| A09 | P0 | Fatal crash and data loss | Crash recovery and autosave verified under forced termination | OPEN |
| A10 | P0 | CMake-omit legitimacy | Every omitted product-critical function either implemented or declared unavailable | OPEN |
| A11 | P0 | K2 full product generation | Memory admission, mmap progress, first real token and completion, no OOM | OPEN/BLOCKED_OOM |
| A12 | P0 | Source inventory | 100% files listed with path/hash/classification; local src/win32app reconciled | OPEN |
| A13 | P0 | Target attribution | Every selected CMake TU plus object/link-map entry; orphan code classified | OPEN |
| A14 | P0 | Findings adjudication | No unresolved real P0 or P1 in linked code; all false positives labeled | OPEN |
| A15 | P0 | Promotion authority | Formal gate conjunction from reproducible receipts, never manually forced | HELD |

## Agentic functionality

| ID | Priority | Feature | Pass criteria |
|---|---|---|---|
| G01 | P1 | Ask mode | Read/search/explain only, no project mutation |
| G02 | P1 | Agent mode | End-to-end read/edit/test tool loop using selected model |
| G03 | P1 | Plan mode | Ordered steps, approval, modify, skip and audit trail |
| G04 | P1 | Debug mode | Actual debugger attach/launch/break/step/stack/watch integration |
| G05 | P1 | Auto mode | Routing by task/capabilities/resources, with visible decision and fallback |
| G06 | P1 | Model registry | Live local model list and GGUF inventory; optional cloud connections OFF by default |
| G07 | P1 | Model ensemble | Select 1–16 model identities with backend/routing fields |
| G08 | P1 | Execution topology | Sequential chain, parallel fanout, staged fan-in, iterative critique, per-model result |
| G09 | P1 | Concurrency fairness | No model starvation; per-model timeout and policy |
| G10 | P1 | Stop/cancel | Cancels generation, active terminal, descendants and queued tools promptly |
| G11 | P1 | Pause/resume | Consistent persisted state and safe repeat |
| G12 | P1 | Checkpoint/rollback | Selected or all file changes reverted from atomic snapshots |
| G13 | P1 | Multi-workspace | Unique run IDs, durable provenance, worktree isolation and conflict handling |
| G14 | P1 | Tool dispatch | Every advertised schema mapped to a registered callable tool |
| G15 | P1 | Tool errors | Invalid args, timeouts, permission rejects and process failures truthfully reported |
| G16 | P1 | Headless `/api/tool` | Local-only bind enforced; E2E authorized call and denied remote call |
| G17 | P1 | Extension host | Plugin load/activate/deactivate, crash containment, trust prompts |
| G18 | P1 | Browser/OS authority | Browser navigation, click, type, focus, denial paths and host validation |
| G19 | P1 | MOTD gate | Per-session ACK, restart, cancellation and policy tests |
| G20 | P1 | Agent metrics | Files edited, edits approved, tools run, task success, context/tokens, model speed |

## Polished IDE UI

| ID | Priority | Feature | Pass criteria |
|---|---|---|---|
| U01 | P1 | Composer | Ask/Agent/Plan/Debug modes, model chooser, attachments/context chips |
| U02 | P1 | Chain-of-models picker | 1–16 model tiles, sequence/parallel toggle, cost/VRAM indicators |
| U03 | P1 | Real progress | Run timeline with queued/running/waiting/finished/failed tool nodes |
| U04 | P1 | Review changes | Changed file count, inline diff, per-hunk Accept/Reject and Accept All |
| U05 | P1 | Stop control | Cancels actual tasks; UI state synchronizes with process state |
| U06 | P1 | Background terminal | Live PTY/ConPTY streaming, tabs, profiles, shell exit code and keyboard control — stream owner SOURCE_WIRED (`CONPTY_STREAM_OWNER_001`/`Win32TerminalManager`); RELINK_REQUIRED; RUNTIME NOT_RUN; ≠ PASS |
| U07 | P1 | Dock layout | Sidebar/editor/chat/terminal resize, snap, restore, DPI and monitor changes |
| U08 | P1 | Audit/review tab | Receipt viewer with source path:line, exception, commit and hash |
| U09 | P1 | Session/history | Durable chats, restore, search, linked diffs and branch context |
| U10 | P1 | Context management | Explicit token budget, trimming, retrieval trace and privacy controls |
| U11 | P1 | Explorer and quick open | Real file tree watching, navigation, filter and rename/delete confirmations |
| U12 | P1 | Editor core | Unicode, undo/redo, search/replace, selections, save conflict resolution |
| U13 | P1 | LSP | Hover, definition, references, diagnostics, rename, code actions |
| U14 | P1 | Debugger UI | Watches, breakpoints, stacks, threads, logpoints and source mapping |
| U15 | P1 | Accessibility | Keyboard, screen reader labels, focus ring, zoom, high contrast |
| U16 | P2 | Visual consistency | Component/theme tokens, spacing, typography, reduced motion and error states |
| U17 | P2 | Responsive UX | Smaller windows, multi-monitor, DPI scaling and long conversation performance |
| U18 | P2 | Notifications | Actionable non-blocking states, zero invented completion toasts |

## Inference and runtime

| ID | Priority | Feature | Pass criteria |
|---|---|---|---|
| I01 | P1 | GGUF families | Architecture-specific actual token production across supported dense/MoE models |
| I02 | P1 | Quantization | Oracle-level arithmetic tolerance gates by quant type and layer |
| I03 | P1 | CPU/GPU fallback | Observable dispatch, no hidden slow fallback, device health and recovery |
| I04 | P1 | Vulkan GEMV | Repair fullView failures; measure real GPU-resident token decode |
| I05 | P1 | Vulkan synchronization | Measured GPU path including attention and nonblocking scheduling |
| I06 | P1 | Multi-GPU | R9700 32GB + RX 7800 XT 16GB correctness/throughput and placement |
| I07 | P1 | Long context | Logical context validated independently from physical KV placement |
| I08 | P1 | MoE scheduler | Expert cache hits, H2D, prefetch overlap, deterministic output |
| I09 | P1 | Memory protection | Admission, bounded RSS/VRAM, graceful refusal before OOM |
| I10 | P1 | Model switching | Seamless cancel/unload/reload and no session cross-talk |
| I11 | P1 | Concurrency | Real 1,2,4,8,16 agent tests with fair throughput and no state mixing |
| I12 | P1 | Performance seals | Per-model TPS on real tokens with same binary/config/prompt/hardware |

## Engineering, security and release

| ID | Priority | Feature | Pass criteria |
|---|---|---|---|
| Q01 | P1 | Reproducible builds | Exact toolchain pins, clean build and hash provenance |
| Q02 | P1 | Static quality | Compiler warnings, Cppcheck/clang-tidy, all HIGH issues adjudicated |
| Q03 | P1 | Sanitizers and diagnostics | ASan/UBSan where supported, MSVC runtime checks, pageheap/appverifier |
| Q04 | P1 | Fuzzing | GGUF/parser, JSON/tool schemas, file paths, IPC and HTTP routes |
| Q05 | P1 | Unit/integration | Real, deterministic tests with negative controls and failure injection |
| Q06 | P1 | UI E2E | Win32 HWND-based user-flow automation on shipping EXE, screenshots/logs |
| Q07 | P1 | Soak | Long-running IDE + inference + agent interactions, no leaks/crashes |
| Q08 | P1 | Secret handling | Local-only default, no accidental upload or secret leakage in logs |
| Q09 | P1 | Plugin sandbox | Extension isolation, minimum privileges, signed/approved integrations |
| Q10 | P1 | Dependency security | SBOM, pinned dependencies, license and CVE review |
| Q11 | P2 | Packaging | Correct installer, uninstall, updates, signing and Windows Defender scan |
| Q12 | P2 | Documentation | Accurate features, supported models, limitations, recovery guide |
| Q13 | P2 | User acceptance | Repeated real project workflow tests and usability criteria |
| Q14 | P2 | CI gates | Release/Debug, x64, selected no-Vulkan, CPU only and test artifacts |

## Evidence and promotion procedure

1. Freeze local Git HEAD, dirty diff, toolchain, exact binary path, SHA-256, and source manifest.
2. Generate CMake File API codemodel and MSVC linker map for the Win32IDE target. Do not treat unselected source as a shipping defect, but record intentional omissions.
3. Inspect all source directories, including root-level code, legacy, ignored/untracked source and duplicated implementations; classify every source as LINKED, BUILD-SELECTED, TEST-ONLY, OMIT-GATED, ARCHIVED, GENERATED, or UNKNOWN.
4. Review heuristic findings with independent owner adjudication. Capture minimal path:line evidence, do not falsely count every TODO/return false as a bug.
5. Close P0 first, rebuild to a new SHA, then rerun all SHA-bound proof ladders and negative controls.
6. Run IDE E2E tests and full multi-model agent loops; require actual process completion and genuine model tokens, never synthetic receipts.
7. Perform security, accessibility, stress, soak and regression matrix on the same shipping artifact.
8. Only after mandatory gates are backed by successful receipts may a separate authority workflow evaluate PROMOTE. This report never changes that status.

**Release rule:** `SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`, `NOT_RUN != PASS`, and `historical PASS != current tip PASS`.
