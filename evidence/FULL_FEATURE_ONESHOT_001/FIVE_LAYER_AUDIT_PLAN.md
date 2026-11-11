# FIVE_LAYER_AUDIT_PLAN — FULL_FEATURE_ONESHOT_001

ASOF_UTC=2026-11-09T12:40:00Z
CONTROLLING_TIP=CC79
CONTROLLING_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MERGE_AUTHORIZED=0
INVENT_PASS=0
STATIC≠RUNTIME_PASS=1

## Purpose

Trace release-scope features through five graphs. Static RE can mark INVESTIGATE/CONFIRMED-source; only measured SHA receipts can flip UNVERIFIED→PASS/FAIL for product gates.

## Layer 1 — Build graph

**Goal:** feature → CMake target → TU → linked symbol (sample H01–H12 on Ext/Native).

| Slice | Method | Status |
|-------|--------|--------|
| L1-S1 Native vs Ext admission | Parse `CMakeLists.txt` `RAWRXD_NATIVE_IDE_SOURCES` / `RAWRXD_NATIVE_IDE_EXT_SOURCES` | **EXECUTED** |
| L1-S2 Debugger TU | `Win32IDE_Debugger.cpp` in Native list; Ext list additive for host/worker | **EXECUTED** |
| L1-S3 Orphan / disabled targets | Count `if(FALSE)` CMake guards | **EXECUTED** (11 blocks) |
| L1-S4 Qt default OFF | `RAWRXD_BUILD_WIN32IDE_QT` default OFF | **EXECUTED** |
| L1-S5 Ext option OFF-by-default | `RAWRXD_NATIVE_IDE_EXT` OFF; Ext SKIPPED without QuickJS | **EXECUTED** |
| L1-S6 Clean-checkout full feature→symbol map | Full inventory | NOT_RUN (I57-A05 OUT_OF_SCOPE enterprise; A06 mandatory remains OPEN) |
| L1-S7 Reproducible SHA twin rebuild | Identical source → same SHA | NOT_RUN (H12) |

### L1 measured notes (this audit)

```
NATIVE_SRC_ROWS≈31 (parser sample; not full inventory claim)
EXT_ADDITIVE_SAMPLE=
  js_extension_host / extension_polyfill_engine / plugin_signature /
  vscode_extension_api / quickjs_extension_host / quickjs_vscode_bindings /
  Win32IDE_ExtHostWire
HAS_DEBUGGER_IN_NATIVE=1
IF_FALSE_BLOCKS=11  # includes test_terminal + RawrXD-Chat legacy (D014 overlap)
QT_DEFAULT=OFF
EXT_OPTION_DEFAULT=OFF
EVIDENCE=artifacts\MASTER_AUDIT_MEASURE_001.txt + this file
```

H01–H12 disposition after L1 sample: remain **INVESTIGATE** / **UNVERIFIED** except overlaps noted in master register (no invented CONFIRMED from compile alone).

## Layer 2 — Command graph

**Goal:** release-scope menus/tools → handlers → observable result.

| Slice | Method | Status |
|-------|--------|--------|
| L2-S1 Chat Ctrl+Enter AIM 7/7 | Sealed receipt on CC79 | **SEALED** (CHAT_CTRL_ENTER) — ≠ tip_chat_dispatch 17-series |
| L2-S2 Terminal ConPTY smoke | tip_final_005 / CC79 | **SEALED** TERMINAL=PASS |
| L2-S3 Build Project / Output HWND | oneshot tip005/tip006 harness | OUTPUT_HWND=FAIL (oneshot axis); FINAL_COMPLETION OUTPUT_GUI=PASS sealed CC79 — **axis-separated; no merge** |
| L2-S4 Problems click-to-line | CC79 items=0 FAIL; 47451F24 PASS (exe ABSENT live) | **MEASURED** |
| L2-S5 Full menu invoke matrix | Every release command | NOT_RUN (H13–H15) |
| L2-S6 tip_chat_dispatch 17-probe | Owned by worker 9643a336 | **NOT_CLAIMED_HERE** (false-DONE forbidden) |

## Layer 3 — Lifecycle graph

**Goal:** HWND / thread / pipe / session ownership.

| Slice | Method | Status |
|-------|--------|--------|
| L3-S1 Extension load→activate→cmd→deactivate | CC79 EXT_LOAD=PASS (fixture); 47451 EXT_CLEANUP=FAIL | **MEASURED** |
| L3-S2 AgentSession cancel/orphan | PR78 gates | OPEN / NOT_RUN |
| L3-S3 Compiler pipe + VS_UNICODE_OUTPUT | CC79 Problems FAIL root-cause; scrub fix on 47451 | **CONFIRMED historical** (H27) |
| L3-S4 Stale HWND after destroy | H16 / PR78 | INVESTIGATE / NOT_RUN |

## Layer 4 — Failure graph

**Goal:** cancel / timeout / fault for compiler / chat / ext.

| Slice | Method | Status |
|-------|--------|--------|
| L4-S1 Ext malformed fault isolation | CC79 fixture MALFORMED_FAULT_ISOLATED=1 | **SEALED** on CC79 EXT path |
| L4-S2 Ext quit within bound | 47451 `--ext-quit` FORCE_KILL → EXT_CLEANUP=FAIL | **CONFIRMED** on 47451 |
| L4-S3 Compiler cancel descendants | H29–H30 | INVESTIGATE / NOT_RUN |
| L4-S4 Chat exactly-once / cancel | tip_chat_dispatch | NOT_VERIFIED (owner 9643a336) |

## Layer 5 — Acceptance graph

**Goal:** mandatory feature → test → SHA → receipt.

| Slice | Method | Status |
|-------|--------|--------|
| L5-S1 Fold GitHub mandatory daily-driver | GITHUB_ACCEPTANCE_EXTRACT.md | **ABSORBED** |
| L5-S2 Fold OUT_OF_SCOPE I57/PR75/PR76 | same | **ABSORBED** |
| L5-S3 CC79 five cross-subsystem gates | FINAL_COMPLETION + oneshot receipts | **RECONCILED** (see FINAL_VERDICT / register) |
| L5-S4 Issue #49 product-final one SHA | | **NOT_DEMONSTRATED** |
| L5-S5 Finish-25 current recount | | HIST 19/25; CURRENT 4/25 |

## Execution law

```
EXECUTED_SLICE ≠ PRODUCT_PASS
SEALED_ON_CC79 ≠ INTEG_004_LIVE_69FE
47451_PROBLEMS_PASS ≠ CONTROLLING
TIP_CHAT_OWNER=9643a336  # do not seal EXACTLY_ONCE here
PROMOTE=0 CERTIFIED=0 MERGE_AUTHORIZED=0
```

## Absorb stamp (2026-11-09T12:48Z)

LOCAL_INTEG004_FINISH25_INVENTORY=ABSORBED (sibling 171cbe2a)
GITHUB_ACCEPTANCE_EXTRACT=ABSORBED (sibling c05247c5)
MASTER_HIDDEN_GAP_REGISTER=WRITTEN
INTEG_004_SHA_DRIFT=1 (47451 sealed != 69FE live)
TIP_CHAT_OWNER=9643a336 EXACTLY_ONCE=NOT_CLAIMED
ACCEPTANCE_REGISTER_78=ABSENT
FINISH25_HIST=19/25 FINISH25_CUR=4/25
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0 CERTIFIED=0 MERGE_AUTHORIZED=0
