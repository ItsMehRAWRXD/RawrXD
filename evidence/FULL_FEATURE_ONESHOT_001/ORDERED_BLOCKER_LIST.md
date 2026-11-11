# ORDERED_BLOCKER_LIST — smallest set unlocking integrated workflow

ASOF_UTC=2026-11-09T14:50:00Z
PROMOTE=0
MATURITY=82_UNCHANGED
CONTROLLING_TIP=CC79
SOURCE=HIDDEN_GAP_AUDIT_001 FINAL + oneshot gates + user PS routing report

Priority = dependency order for **one candidate SHA**. Symptoms below parents are not separate first repairs.

| Pri | Blocker | Evidence class | Unlocks |
|-----|---------|----------------|---------|
| P0 | **One candidate EXE** (absorb HWND 1604, INPUT_EVENT journal, PS routing fixes) | Process | All later gates |
| P1 | **Output Build HWND + Problems + click-to-line** on that SHA | tip006 FAIL sealed; 30B9 repair PASS ≠ inherit | Compile/nav chain |
| P1 | **PowerShell panel routing** (`ls`→pane listing; no `[powershell]` chat leak) | User report; gate NOT_RUN | Terminal/PS leg of four-panel |
| P1 | **VS_UNICODE_OUTPUT / Problems env scrub** (H27) on candidate | CONFIRMED on CC79 history | Stable Problems |
| P2 | **Chat input events** (Ctrl+Enter / Send one-dispatch) + session_id bind on candidate | Correlation≠PASS; INPUT_EVENT gate contested/SHA-split | Model response leg |
| P2 | **AgentSession ownership + cancel** (H57) | CONFIRMED source membership split | Tool action + cancel/recovery |
| P2 | **ExtensionHost cleanup FORCE_KILL=0** (H51) | CONFIRMED SHA-scoped on INTEG_004 | Ext shutdown + clean exit |
| P3 | **Debugger UI** (four-panel) | CC79 IDE_DEBUG_UI=FAIL | Four-panel conjunction |
| P3 | **Four-panel conjunction** Ext+Chat+Term+Output(+Debug) | OPEN | Integrated acceptance |
| P4 | **Issue #49 product-final E2E** | OPEN; maturity-change yardstick only | Maturity reassess |
| P5 | **Package + clean-machine + rollback** | NOT_RUN | Delivery seal |

## Explicitly NOT first-line

- H01/H04 CMake/feature-flag inventory — fold into P0 candidate link map, don't solo-chase
- H87 GPU device-loss specialty — not on daily-driver chain unless model path requires
- H113 stub backends — only if selected on candidate product path
- 120 INVESTIGATE / 56 UNVERIFIED — no arithmetic; chase only if a P0–P3 gate fails
- Parallel tip packages (30B9, 2B1D, C43B, tip006) — absorb, don't remeasure all

## Law

```
INVESTIGATE ≠ CONFIRMED
PARTIAL_TIP_PASS ≠ INTEGRATED_PASS
100% = AGREED_GATES_ON_FINAL_SHA
PROMOTE_AND_CERT_SEPARATE=1
```
