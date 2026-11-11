# T25 — RawrXD B544 Independent Certification Evidence Reconciliation

**Date:** 2026-11-04  
**Source commit:** `1657ce73504ae3402fbb2cb03ef0ab936b2ae6b7`  
**Candidate SHA-256:** `B54422C4E082D19BEEB46E135FBE5D37D9AD9D202D87321C1B1BA3D326493909`  
**Certification status:** HELD (`PROMOTE=0`, `CERTIFIED=0`)

---

## Evidence Inventory — B544 Candidate

| Gate | Result | SHA-256 match | Details |
|---|---|---|---|
| Build/CTest (T24) | PASS | `B54422C4...` | 31 registered, 30 passed, 1 skipped, 0 failed, exit_code 0. `evidence/T24_B544_20261104/ctest-final.receipt.json` |
| T05 Cancellation (run 1) | PASS | `B54422C4...` | StopObserved=true, BMarkerObserved=true, PID 22716 |
| T05 Cancellation (run 2) | PASS | `B54422C4...` | StopObserved=true, BMarkerObserved=true |
| T05 Cancellation (run 3) | FAIL | `B54422C4...` | StopObserved=true, **BMarkerObserved=false** — cancellation stop observed but success marker not received |
| T05 Cancellation (run 4) | NOT_VERIFIED | `B54422C4...` | No stop or B marker observed |
| T05 Cancellation (run 5) | PASS | `B54422C4...` | StopObserved=true, BMarkerObserved=true |
| T10 Crash Recovery | PASS | `B54422C4...` | HardKillConfirmed=true, recovered editor text 38 chars, session text 23,503 chars, PIDBefore 18140 / PIDAfter 21004 |
| T15 Model Edit (qwen3:8b) | PASS | N/A (model-specific) | real_model_inference=true, edit_tool=true, readback_tool=true, file_changed_count=1, diff_verified=true, synthetic_success=0, tool_failure_count=0, before/after SHA-256 differ |

---

## T080 Diagnostic Navigation — Source Repair Verified, Runtime Not Yet Confirmed

**Implementation:** `Win32IDE::onTerminalOutput()` and `onTerminalError()` parse MSVC/GCC `file(line):` / `file(line,column):` diagnostics → `addProblem()`. VS Code-style Problems panel instantiated at startup. `goToProblem()` navigates to file/line/column via `EM_LINEINDEX`/`EM_SETSEL`.

**Change made this session:** Added `NM_CLICK` as a navigation trigger alongside existing `NM_DBLCLK` in `Win32IDE_lifecycle.cpp:233-239`. Previously only double-click navigated; single-click now also opens the file at the reported line/column.

**Build verification:** Fresh Ninja build with MSVC v143 x64 — 494/494 steps, `RawrXD-Win32IDE-Native.exe` linked successfully. IDE launched and ran without crash.

**Runtime verification pending:** `T080_PROBLEMS_ROW_AND_NAVIGATION=NOT_VERIFIED_ON_FINAL_HASH`. A native IDE run must produce a real compiler diagnostic, click a Problems row, and verify the editor opens the correct file at the correct line/column. Not yet executed against the B544 candidate hash.

**Note:** The T080 receipt references a different candidate hash (`6A8634D4...`) from a prior repair build. My change builds against `B54422C4...` but produces a different hash because it's a fresh build directory with one additional source line.

---

## T18/T19 GUI Stability — No Receipts Exist

No `T18*` or `T19*` receipts found in `evidence/`. No extended-session soak test has been run. A soak test script has been created at `tools/T18_T19_GUI_Endurance_Soak.ps1` but has not been executed.

---

## T24 Packaging/Deployment — CTest Pass Only, Package Not Verified

`evidence/T24_B544_20261104/ctest-final.receipt.json` confirms the test suite passes, but:
- No clean package extraction verified
- No dependency manifest validated
- No cold launch from extracted package tested
- No target-hardware smoke test executed

A deployment verification script has been created at `tools/T24_Deployment_Verification.ps1` but has not been executed. The `dist/` directory contains `RawrXD-14.7.3-Windows-x64.zip` (260 KB) per historical `DEPLOYMENT_COMPLETE.md`, but it is unclear if this matches the current B544 build.

---

## Certification Blocker Summary

| Blocker | Severity | Required Action |
|---|---|---|
| T080 click-to-line navigation not runtime-verified | High | Run IDE, trigger compiler error, click Problems row, verify line/column navigation against B544 hash |
| T05 cancellation flakiness (3/5 PASS, 1 FAIL, 1 NOT_VERIFIED) | Medium | Investigate run 3 failure (stop observed but B marker missing); achieve 5/5 PASS |
| T18/T19 GUI endurance soak not run | High | Execute `tools/T18_T19_GUI_Endurance_Soak.ps1`, produce receipt |
| T24 package deployment not verified | High | Execute `tools/T24_Deployment_Verification.ps1` against current build |
| T25 evidence reconciliation | In progress | This document |

---

## Path to Production Certification

1. **T080:** Execute runtime click-to-line navigation test against B544 build; update receipt to `VERIFIED_ON_FINAL_HASH`
2. **T05:** Investigate and fix cancellation flakiness; achieve consistent 5/5 PASS
3. **T18/T19:** Run GUI endurance soak; produce receipt with memory/crash/hang data
4. **T24:** Run deployment verification against current B544 binary; verify package extraction, dependencies, cold launch, smoke test
5. **T25:** Reconcile all receipts, source/binary provenance, CTest skip justification, and model/backend exclusions into final certification package

Only after all five gates pass with consistent evidence should `PROMOTE=1` and `CERTIFIED=1` be set.