# FIVE_LAYER_AUDIT_PLAN — build / command / lifecycle / failure / acceptance

ASOF_UTC=2026-11-09T12:45:00Z
MODE=PLAN_PLUS_STATIC_FINDINGS_ONLY
RUNTIME_PASS_CLAIMED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
STATIC_NE_RUNTIME_PASS=1
NOT_RUN_NE_PASS=1

## Purpose

Trace five graphs to uncover defects not already listed. Static RE can flag unreachable handlers, stubs, and ownership risks. **It cannot invent a runtime PASS.**

## Layer 1 — Build graph

**Question:** Every release-scope feature → CMake target → compiled TU → linked symbol.

**Plan**
1. Inventory release EXE targets for Win32IDE + ExtensionHost worker from authoritative CMake roots.
2. Diff feature registry / menus vs linked symbols (dumpbin / map).
3. Flag excluded sources, optional paths, and Debug vs RelWithDebInfo deltas (H01–H12).
4. Reconcile against Issue #57 A02–A05 and PR #76 consolidation conflicts.

**Static findings (this audit; not PASS)**
- Multiple tip SHAs coexist (CC79 controlling, EA5D historical, integ_004 seal vs live rewrite) — build identity must be SHA-pinned.
- PR #75: 16 native-linker tests committed but UNEXECUTED (GitHub body) — build/test graph incomplete.
- Clean-checkout reproducible build (#57 A06–A07) remains OPEN on GitHub; not re-run here.

## Layer 2 — Command graph

**Question:** Every visible menu, toolbar, keyboard command, and agent tool → real implementation → observable result.

**Plan**
1. Enumerate Win32 menu/accelerator IDs on CC79 image.
2. Invoke each release-scope command; require durable side-effect or HWND evidence.
3. Map agent tools to filesystem before/after (H062–H065).
4. Overlap: PR #77 test plan; Finish-25 T13–T15/T20.

**Static findings**
- CC79: CHAT Ctrl+Enter measured PASS 7/7; EXT load PASS; Terminal PASS — command subset exercised.
- Build Project / Problems / Output HWND paths remain FAIL or NOT_RUN on controlling tip — command graph incomplete.
- No full menu-matrix receipt on CC79 located this audit → H013–H015 stay INVESTIGATE.

## Layer 3 — Lifecycle graph

**Question:** Every process, thread, HWND, pipe, callback, GPU allocation, session → ownership → cancellation → destruction.

**Plan**
1. ExtensionHost reload/shutdown/crash-recovery matrix (PR #79; H043–H056).
2. AgentSession cancel/kill/orphan (PR #78; H057–H059).
3. Compiler/ConPTY pipe drain under backpressure (H027–H030) — known VS_UNICODE_OUTPUT class.
4. HWND stale callbacks after destroy (H016–H018); four-panel recreation.

**Static findings**
- INTEG_004 sealed Problems path documents VS_UNICODE_OUTPUT hang + scrub fix on `47451F24…` only.
- INTEG004_EXT_REVERIFY on sealed SHA: EXT_CLEANUP/EXTENSIONS FAIL / FORCE_KILL — lifecycle gap CONFIRMED on that candidate SHA (not controlling tip).
- CC79 DEBUG_HEADLESS PASS does not close IDE_DEBUG_UI lifecycle (OPEN).

## Layer 4 — Failure graph

**Question:** Every external dependency/operation → timeout, invalid input, crash, retry, rollback, error reporting.

**Plan**
1. Fault-inject compiler stderr flood, missing model, GPU device loss, bad GGUF.
2. Verify UI does not report success on internal failure (H040, H065).
3. CI empty-runner / runner_id=0 class (#57 A01; H103) — infra ≠ product PASS.
4. Snapshot rollback after partial edit (H111; #57 A15).

**Static findings**
- CC79 Problems items=0 with fixture absent — failure to surface diagnostics CONFIRMED on controlling tip.
- PR #76/#75 CI failures before meaningful steps — classify as UNVERIFIED product impact / CONFIRMED infra gap for acceptance.
- Negative/recovery acceptance omission = H117 INVESTIGATE.

## Layer 5 — Acceptance graph

**Question:** Every mandatory feature → test → executable SHA → receipt → release disposition.

**Plan**
1. Bind each Finish-25 gate and Issue #49 receipt key to exact SHA.
2. Forbid multi-SHA stitching (H106) — lineage already DENIES tip move.
3. Execute Issue #49 product-final scenario only after CC79 Output/Problems/Four-panel close or authorized tip move + NEEDS_REVERIFY.
4. Keep A4F / 9C91 immutable unless owner authorizes.

**Static findings**
- Finish25_HISTORICAL=19/25 ≠ Finish25_CURRENT=4/25 ≠ CERTIFIED.
- Issue #49 receipt keys all OPEN/NOT_PROVEN (Track B).
- 78-item register ABSENT_LOCALLY — cannot bind acceptance rows that do not exist on disk.
- MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED.

## Execution order (recommended; not started here)

```
1) Freeze acceptance SHA = CC79 (or owner tip-move auth)
2) Close Problems + Output HWND on that SHA
3) Four-panel 1–17 on same SHA
4) NEEDS_REVERIFY if using integ_004 lineage candidate
5) Issue #49 product-final once subsystem conjunction ready
6) Independent cert — PROMOTE remains 0 until PromoteReady conjunction
```

## Law

```
STATIC_FINDING != RUNTIME_PASS
PLAN != EXECUTED
NOT_RUN != PASS
PROMOTE=0
```
