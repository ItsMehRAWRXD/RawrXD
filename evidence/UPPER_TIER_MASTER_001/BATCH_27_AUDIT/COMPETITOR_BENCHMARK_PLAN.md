# COMPETITOR_BENCHMARK_PLAN — Upper-Tier §12 / Batch 27

**Plan:** `UPPER_TIER_MASTER_001_BATCH_27_AUDIT_COMPETITOR_BENCHMARK_PLAN`  
**Scope:** `F:\rawrxd` (read-only plan)  
**Authority:** master plan §12 + `TRACKER.json` + Batch 19/20/22 audits  
**Date:** 2026-11-11  

```
CERTIFIED=0
PROMOTE=0
UPPER_TIER=0
TIP_CLIMB=HOLD
STUB_ACCEPTANCE=FORBIDDEN
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
NO_INVENT_SCORES=1
BATCH_27_MILESTONE=NOT_EVALUATED
```

Tracker estimates unchanged (not raised by this plan): engineering 82% · release 58% · AI IDE 69% · traditional IDE 63%.

## Framing

| Field | Value |
| --- | --- |
| §12 | Upper-tier benchmark acceptance matrix |
| Batch 27 workstreams | Competitor suite, performance tuning, reliability tuning, usability validation, parity audit |
| Required milestone | **Upper-tier status evaluated** |
| This packet | **Plan only** — no comparative runs, no scores |

Controlling shared blocker: **G1 native exe absent** (`TRACKER.native_exe=ABSENT`, `BLOCKED_ON_BATCH17_EXE=1`). Batch 27 evaluation presupposes Batches 17–26 product-path milestones.

## Competitor set (planned, not run)

| Class | Planned subjects |
| --- | --- |
| AI-native | Cursor; GitHub Copilot / VS Code agent surfaces; other licensed AI IDE (TBD before run) |
| Traditional | VS Code stable; Visual Studio 2022 (C++/debug baseline where applicable) |
| Subject | Tip-linked `RawrXD-Win32IDE-Native.exe` SHA (**ABSENT today**) + Deep2 headless where row allows |

## Hardware notes (required fixture spec — not measured)

- Same machine, OS build, thermal/power profile, and network-isolation policy across competitors.
- Record: CPU model/cores, RAM free, GPU vendor/model/VRAM/driver/backend, storage type, DPI/monitors.
- Inference rows: pin model SHA/quant; label CPU vs Vulkan/CUDA/ROCm; no silent backend switch.
- Offline-first RawrXD claims must be labeled OFFLINE; competitor ONLINE defaults must be labeled ONLINE.
- Release row: separate clean VM/image (no developer-machine contamination).

## Shared fixtures (status)

| Fixture | Status |
| --- | --- |
| Held-out repos + independent oracle | ABSENT as sealed suite (`AGENT_E2E_001` ≠ held-out multi-repo) |
| Critical-workflow reliability suite (≥99% proposed) | ABSENT sealed |
| Editing suite | NOT_DEFINED as Batch 27 packet |
| LSP latency harness | NOT_RUN on product tip |
| Debug E2E fixture | NOT_RUN on product tip |
| Inference oracle | PARTIAL internal only (N01/N02 candidate; N03–N05 OPEN; external oracle PROMOTE=0) |
| Concurrency stress | NOT_RUN true-parallel (mutex-serialized multi ≠ parallel) |
| Extension compat suite | RUNTIME_REACHED=0/10 (Batch 22) |
| Soak / crash recovery | PARTIAL historical GUI soak ≠ comparative B27 pass |
| Clean-machine install | NOT_RUN |
| Authoritative candidate SHA | ABSENT (P16 open) |

## Acceptance matrix

| Benchmark | Required result (master plan) | Measurable workflow | Score | BLOCKED_ON |
| --- | --- | --- | --- | --- |
| Autonomous coding | Held-out repo tasks, independently verified | Inspect→edit→build→test→verify + oracle | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; BATCH_20_AGENT_LOOP_NOT_ACCEPTED; HELD_OUT_REPO_SUITE_ABSENT; INDEPENDENT_ORACLE_ABSENT_AS_SEALED_SUITE |
| Agent reliability | ≥99% critical workflow pass rate | Tool dispatch / cancel / atomic edit / exactly-once / bounds / fault-injection suite | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; RELIABILITY_SUITE_ABSENT_SEALED; BATCH_20_RUNTIME_PASS_0_OF_6; CANCEL_RECOVERY_RUNTIME_PASS_0 |
| Editing | Core editing suite, no data loss | Open/save/search/undo/encoding/crash-recovery vs traditional baseline | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; BATCH_18_GUI_INTERACTIVE_ACCEPTANCE_NOT_SEALED_FOR_B27; EDITING_SUITE_PACKET_ABSENT |
| LSP | Correctness + latency competitive | Completion/hover/goto/refs/rename + p50/p95 vs VS Code/VS | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; P01_P04_LSP_COMPILATION_CRITICAL_PATH_OPEN; LSP_RUNTIME_ACCEPTANCE_NOT_SEALED |
| Debugging | Real launch/attach/breakpoint/inspection | Launch→BP→step→locals→terminate | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; BATCH_21_LANGUAGE_DEBUG_ACCEPTANCE_NOT_SEALED; DEBUG_E2E_FIXTURE_NOT_RUN_ON_TIP |
| Inference | Accuracy parity + measured TPS/TTFT | Load→prefill→decode→stream→unload; single+multi | NOT_MEASURED | N03_SESSION_ISOLATION_RECEIPT_ABSENT; N04_TRUE_PARALLEL_OPEN; N05_E2E_STRESS_OPEN; P13_STILL_OPEN; EXTERNAL_ORACLE_PROMOTE_0 |
| Concurrency | Stable multi-session + multi-agent stress | Concurrent sessions/agents; fairness; no deadlock/data-loss | NOT_MEASURED | N04_TRUE_PARALLEL_OPEN; N05_E2E_STRESS_OPEN; G1_NATIVE_EXE_ABSENT; MULTI_AGENT_STRESS_SUITE_ABSENT_SEALED |
| Extensions | Supported API contract compatibility suite | Discover→activate→command→isolate→disable | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; BATCH_22_RUNTIME_REACHED_0_OF_10; VSCODE_JS_ACTIVATE_UNPROVEN; F_PRODUCT_EXTENSION_RUNTIME_ABSENT_OR_STUB |
| Stability | Extended soak + crash recovery | Soak duration + restart restore + leak counters | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; BATCH_25_RELEASE_CANDIDATE_ACCEPTANCE_NOT_SEALED; COMPARATIVE_SOAK_PACKET_ABSENT |
| Release | Reproducible clean-machine install/operate | Clean install→smoke→upgrade/uninstall + SHA manifest | NOT_MEASURED | G1_NATIVE_EXE_ABSENT; P16_AUTHORITATIVE_SHA_UNRESOLVED; P17_PACKAGING_RUNTIME_DEPS_OPEN; P18_FINISH25_HELD; T25_HELD; CERTIFIED_0; PROMOTE_0 |

**Rows:** 10 · **Measured:** 0 · **Blocked:** 10 · **UPPER_TIER claimed:** false

Proposed thresholds in the master plan are acceptance *targets*, not existing measurements. N01/N02 candidate receipts are cited for inference prep only — `RECEIPT PASS ≠ CERTIFIED`.

## Rollup / next gates

1. Batch 17 G1: linked `RawrXD-Win32IDE-Native.exe` (exit 0, size+SHA).
2. Seal Batches 18–26 product-path acceptances without inventing PASS.
3. Materialize held-out repos + critical-workflow reliability suite fixtures.
4. Lock competitor versions + hardware lockfile before any comparative run.
5. Execute matrix on one authoritative SHA; record scores only from runs.
6. Keep `CERTIFIED=0` `PROMOTE=0` `UPPER_TIER=0` until all eight dimensions + §12 matrix are verified.

```
TARGET=UPPER_TIER_ALL_8_DIMENSIONS
COMPETITIVE_PARITY=BENCHMARK_REQUIRED
CURRENT_CERTIFIED=0
CURRENT_PROMOTE=0
UPPER_TIER=0
```

Machine-readable twin: `COMPETITOR_BENCHMARK_PLAN.json`.
