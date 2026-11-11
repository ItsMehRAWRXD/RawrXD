# Batch 18 — Interactive GUI Runtime Gate Checklist (P06–P11)

```
ASOF_UTC=2026-11-11T18:31:00Z
MODE=CHECKLIST_PREP_VERIFIED
AUTHORITY=F:\rawrxd
CROSS_CHECK=G:\~dev\rawrxd (as needed)
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
SOURCE_WIRED ≠ RUNTIME_REACHED
NOT_RUN ≠ PASS
NO_INVENT_PASS=1
EDITED_PRODUCT_SOURCES=0
RUNTIME_ACCEPTANCE=HELD_PENDING_BATCH_17_EXE
HARNESS_PS_SMOKE=VERIFIED_FAIL_CLOSED
```

## Purpose

Executable interactive GUI acceptance checklist for Batch-18 gates **P06–P11**.
This file is **prep only** until a **new** `RawrXD-Win32IDE-Native.exe` SHA exists under the Batch-17 tip path.

Companion inventory (gap seal, not runtime PASS):

- `GUI_INTERACTIVE_GAP_MATRIX.md`
- `GUI_INTERACTIVE_GAP_MATRIX.json`

## Hard preconditions (fail-closed)

```
EXE_PATH=F:\rawrxd\build_win32ide\Release\RawrXD-Win32IDE-Native.exe
EXE_REQUIRED=1
NEW_TIP_SHA_REQUIRED=1
PRIOR_CANDIDATE_SHA ≠ TIP_ACCEPTANCE
```

| Precheck | Rule | On fail |
|----------|------|---------|
| **G0_EXE_PRESENT** | `Test-Path EXE_PATH` must be true | `STATUS=HELD` · do **not** launch IDE · do **not** mark any Pn PASS |
| **G0_NEW_SHA** | Record SHA-256 of tip exe; must be a **new** tip SHA vs last sealed Batch-17/18 receipt (not prior Ext/ONESHOT/T080/FOUR_PANEL candidates) | `STATUS=HELD` · interactive steps **NOT_RUN** |
| **G0_SHA_BOUND** | Every P06–P11 result row must cite the **same** tip SHA | Mismatched SHA → result invalid · treat as NOT_RUN |

### Current probe (prep seal)

```
EXE_ABSENT=1
EXE_RELEASE=ABSENT
EXE_BIN_RELEASE=ABSENT
TIP_SHA=UNRESOLVED
STATUS=HELD
RUNTIME_REACHED=0/6
PRODUCT_RUNTIME_PASS=0/6
HARNESS_PS_SMOKE=VERIFIED_FAIL_CLOSED (exit 2; LAUNCH=SKIPPED)
GUI_SMOKE_EXERCISED=0
CERTIFIED=0
PROMOTE=0
VERIFY_RECEIPT=VERIFY_RECEIPT.txt
```

**Law:** If EXE absent → entire checklist `STATUS=HELD`. Absence is not FAIL inventing; it is hold. `NOT_RUN ≠ PASS`.

## How to unlock (operator)

1. Complete Batch-17 link so `EXE_PATH` exists (exit 0 build).
2. Compute and seal tip SHA under `BATCH_17/` (and copy into the Result block below).
3. Only then set `PRECONDITION=UNLOCKED` and execute P06→P11 in order on **that** SHA.
4. Leave any unexecuted step as `NOT_RUN`. Never backfill PASS from historical receipts.

```
# Unlock probe (operator; do not invent):
Get-FileHash F:\rawrxd\build_win32ide\Release\RawrXD-Win32IDE-Native.exe -Algorithm SHA256
# Paste SHA into TIP_SHA below; set PRECONDITION=UNLOCKED only if EXE present AND SHA is new tip.
```

## Result ledger (fill only after unlock)

```
PRECONDITION=UNLOCKED
TIP_SHA=D1B17F66C5BD951BADD51FEE31326EAAE758B1E3F605E761AB4D82D255A32ABF
EXE_PATH=F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe
RUN_UTC=2026-11-11T19:15:00Z
OPERATOR=cursor_subagent_batch18
STATUS=RUNTIME_EXERCISED_PARTIAL
P06=PASS
P07=FAIL
P08=FAIL
P09=FAIL
P10=PASS
P11=FAIL
RUNTIME_REACHED=6/6
PRODUCT_RUNTIME_PASS=2/6
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NOTE=User brief SHA 16D85B1C superseded by live tip D1B17F66 at 19:06:28Z; ledger binds live tip only. Evidence under RUNTIME_EVIDENCE/ + DISPOSITION_RUNTIME_GATE.txt
```

Allowed step values only: `NOT_RUN` | `HELD` | `FAIL` | `PASS`  
`PASS` requires live interactive evidence on `TIP_SHA` recorded in this ledger.  
Do **not** credit: SOURCE_APPLIED, prior ONESHOT, T080, FOUR_PANEL_1_17, Ext-host SHAs, or agent narrative.

---

## P06 — PowerShell Execute / Clear / Stop (5610 / 5611 / 5612)

**Requirement:** On tip SHA, Execute / Clear / Stop route correctly; legacy 7100 isolation holds; dock does not regress during PS session.

**Controls:** `IDC_PS_BTN_EXECUTE=5610` · `IDC_PS_BTN_CLEAR=5611` · `IDC_PS_BTN_STOP=5612`

**Harness (optional assist; interactive GUI still required for acceptance):**

```
powershell -NoProfile -File F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_17\PS_SMOKE_HARNESS\Invoke-PsExecuteClearStopSmoke.ps1 -ExePath <TIP_EXE> -AllowLaunch
```

Fail-closed if EXE absent: omit `-AllowLaunch`; expect `LAUNCH=SKIPPED` / `RUNTIME_SMOKE=HELD`.

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P06.1 | Confirm EXE present + SHA matches ledger | SHA bound | |
| P06.2 | Launch Native IDE; open PowerShell panel | Panel visible; no startup crash | |
| P06.3 | Enter a trivial command; click **Execute** (5610) | Output appears; command runs | |
| P06.4 | Click **Clear** (5611) | Console cleared | |
| P06.5 | Start a longer command; click **Stop** (5612) | Execution stops; UI remains responsive | |
| P06.6 | Confirm 7100 isolation (legacy terminal decoder not stealing 5610–5612) | PS buttons still bind to Execute/Clear/Stop | |
| P06.7 | Note dock height / tab state after PS ops | No unexpected dock collapse / tab loss | |

```
P06_RESULT=NOT_RUN
P06_RUNTIME_SMOKE=HELD
P06_NOTE=SOURCE_APPLIED ≠ RUNTIME_PASS; held until new tip SHA
```

Evidence refs: `POWERSHELL_ROUTING_REPAIR_001\DISPOSITION.json` · `BATCH_17\PS_SMOKE_HARNESS\LAW.txt`

---

## P07 — Bottom-dock 4-tab switching

**Requirement:** Interactive switch across Terminal / Output / Problems / Debug Console with HWND visibility proof on tip SHA.

**Controls:** `IDC_PANEL_TABS=1301` · `switchPanelTab` · four inserts

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P07.1 | Confirm tip SHA still bound | Same as ledger | |
| P07.2 | Select **Terminal** tab | Terminal HWND visible; others hidden/obscured per design | |
| P07.3 | Select **Output** tab | Output HWND visible | |
| P07.4 | Select **Problems** tab | Problems list visible | |
| P07.5 | Select **Debug Console** tab | Debug console visible | |
| P07.6 | Cycle tabs twice more | No stall / freeze (`POST_SELECT_MEASURE` must not stall) | |
| P07.7 | Record tab count = 4 | Labels present; `PANEL_TAB_COUNT=4` | |

```
P07_RESULT=NOT_RUN
P07_NOTE=Prior FOUR_PANEL / EA5D receipts ≠ tip acceptance
```

Evidence refs: `EA5D_FOUR_PANEL_GUI_RECEIPT.txt` · `FOUR_PANEL_1_17_RECEIPT.txt` (prior only)

---

## P08 — Dock resize / restore

**Requirement:** Splitter drag resize, maximize/restore, and session `panel.height` reload on tip SHA.

**Controls:** splitter drag · `m_panelHeight` · `maximizePanel` / `restorePanel` · session persist

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P08.1 | Drag bottom-dock splitter up/down | Dock height changes live; floor ≥ 160 | |
| P08.2 | Maximize panel (if UI control present) | Dock expands | |
| P08.3 | Restore panel | Dock returns to prior/non-maximized height | |
| P08.4 | Set a distinctive height; exit IDE cleanly | Session write succeeds | |
| P08.5 | Relaunch same tip SHA | Restored height matches saved `panel.height` | |
| P08.6 | Confirm no layout crash during resize | No FATAL_USER_CALLBACK / exit | |

```
P08_RESULT=NOT_RUN
P08_NOTE=Historical layout SOURCE_FIXED + visual NOT_RUN ≠ tip PASS
```

Evidence refs: `REMAINING_WORK_17_001.txt` · session path via `Win32IDE_Session.cpp` (observe only)

---

## P09 — Problems click-to-line

**Requirement:** Problems item click/activate navigates editor caret to the reported line on **same** tip SHA.

**Controls:** NM_CLICK / DBLCLK / ITEMACTIVATE → WM_COMMAND 1399 · `goToProblem`

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P09.1 | Ensure Problems list has ≥1 real item | Items populated on tip (not stub narrative) | |
| P09.2 | Activate item (click / dbl-click per UI) | Editor opens/focuses target document | |
| P09.3 | Verify caret line | Caret on reported line (`EM_SETSEL` / visible line) | |
| P09.4 | Repeat on a second item if available | Second navigation correct | |
| P09.5 | Confirm SHA unchanged | Still tip SHA in ledger | |

```
P09_RESULT=NOT_RUN
P09_NOTE=T080 / FOUR_PANEL prior PASS not inherited; EA5D CLICK_TO_LINE_HWND was NOT_RUN
```

Evidence refs: `T080_CLICK_TO_LINE_001.txt` (prior) · EA5D receipt (prior NOT_RUN)

---

## P10 — Native IDE startup exceptions

**Requirement:** Cold-start survives without unhandled exception / FATAL_USER_CALLBACK; UI bind reaches interactive state on tip SHA.

**Controls:** WM_CREATE / finishSession layout arm · ensurePanelVisible · startup HWND bind

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P10.1 | Cold-start tip exe (no prior instance) | Process stays up; main HWND visible | |
| P10.2 | Confirm dock/editor bind | UI interactive; not hidden/zombie | |
| P10.3 | Open bottom dock + one editor document | No exception dialog / silent exit | |
| P10.4 | Repeat cold-start ×2 | Stable; no Gate-6-class visibility loss | |
| P10.5 | If crash: capture minidump path + SHA | Record FAIL with provenance; do not invent PASS | |

```
P10_RESULT=NOT_RUN
P10_NOTE=GATE_6 OPEN historically; reopen only with tip provenance — crash ≠ startup PASS
```

Evidence refs: `F_GATE6_CANDIDATE_STARTUP_EXIT_ROOT_001\*`

---

## P11 — Cancellation / recovery

**Requirement:** Stop/cancel then Request B recovery without crash; stale-callback fencing holds on tip SHA.

**Controls:** Stop / cancel HTTP · stale callback fence · post-cancel Request B · GhostText cancel (if exercised)

### Steps

| # | Action | Pass criteria (tip SHA only) | Record |
|---|--------|------------------------------|--------|
| P11.1 | Start Request A (agent/inference runnable on tip) | Request begins; UI shows in-flight | |
| P11.2 | Issue **Stop** / cancel | Cancel completes; no crash / minidump | |
| P11.3 | Issue Request B after cancel | Recovery succeeds; no stale A completion applied | |
| P11.4 | Optional: GhostText cancel / Escape path | Cancel observed; stale fencing holds | |
| P11.5 | Confirm process still interactive | No Gates 04–08 crash class | |

```
P11_RESULT=NOT_RUN
P11_NOTE=Prior BATCH1 Gates 04–08 FAIL + GhostText cancel FAIL ≠ tip PASS
```

Evidence refs: `BATCH1_CANCEL_RECOVERY_001\DISPOSITION.md` · `F_GHOSTTEXT_CANCEL_ROUTING_CLOSURE_001\FINAL_VERDICT.md`

---

## Batch acceptance conjunction

Batch-18 interactive GUI acceptance requires **all** of:

```
PRECONDITION=UNLOCKED
EXE present + NEW tip SHA sealed
P06=PASS ∧ P07=PASS ∧ P08=PASS ∧ P09=PASS ∧ P10=PASS ∧ P11=PASS
same TIP_SHA on every PASS row
```

Until that conjunction is evidenced:

```
STATUS=HELD          # when EXE absent or SHA unresolved (current)
# or STATUS remains non-PASS if any step NOT_RUN/FAIL after unlock
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
UPPER_TIER=0
```

## Forbidden

- Inventing PASS / RUNTIME_REACHED / CERTIFIED / PROMOTE
- Executing interactive steps while `EXE_ABSENT=1`
- Inheriting prior candidate SHA results as tip acceptance
- Editing product sources from this checklist lane
- Raising TRACKER estimates from checklist prep

## Prep seal

```
CHECKLIST=PREPARED_AND_VERIFIED
PATH=F:\rawrxd\evidence\UPPER_TIER_MASTER_001\BATCH_18_AUDIT\RUNTIME_GATE_CHECKLIST.md
GATES=P06,P07,P08,P09,P10,P11
EXE_ABSENT=1
STATUS=HELD
RUNTIME_REACHED=0/6
PRODUCT_RUNTIME_PASS=0/6
HARNESS_PS_SMOKE=VERIFIED_FAIL_CLOSED
GUI_SMOKE_EXERCISED=0
CERTIFIED=0
PROMOTE=0
EDITED_PRODUCT_SOURCES=0
INVENTED_PASS=0
RUNTIME_ACCEPTANCE=HELD_PENDING_BATCH_17_EXE
```

## LIVE_LEDGER_TIP_SHA

## Result ledger (DA52 tip rebind 2026-11-11T19:20:12Z / disposition 19:27:45Z)

```
PRECONDITION=UNLOCKED_AT_RUN
TIP_SHA=DA52DCB69494B8580D3FB4400B06022DD7D1C7BF52F3D11A91FBE438DFC085DE
PRIOR_TIP_SUPERSEDED=D1B17F66C5BD951BADD51FEE31326EAAE758B1E3F605E761AB4D82D255A32ABF
LIVE_DRIFT_RACE=89DC…→D191A14403BBC18DCA8587E31A8EA36D70989E79C1B3DD468FA9CEDA148E0467
EXE_PATH=F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe
RUN_UTC=2026-11-11T19:20:12Z
OPERATOR=batch18_gui_gates_rebind_da52
STATUS=PARTIAL_RUNTIME_REACHED_UNPROMOTED
SHA_BOUND=1
P06=RUNTIME_REACHED_UNPROMOTED
P07=FAIL
P08=FAIL
P09=FAIL
P10=RUNTIME_REACHED_UNPROMOTED
P11=FAIL
RUNTIME_REACHED=6/6
HARNESS_PRODUCT_CLAIM=3/6
PRODUCT_RUNTIME_PASS=0/6
P07_HWND_VIS=FAIL
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NOTE=DA52 gates+followup sealed; P07 HWND anyPaneVis=False; live tip racing — no invent PASS
```


## Result ledger (C25B Collab tip 2026-11-11T19:32:06Z)

```
PRECONDITION=UNLOCKED_AT_RUN
TIP_SHA=C25B157053A590E4BA02A418502A9EF356EE8C386764BB8873B1BD6A098DED5A
PRIOR_TIP_SUPERSEDED=D191A14403BBC18DCA8587E31A8EA36D70989E79C1B3DD468FA9CEDA148E0467
EXE_PATH=F:\rawrxd\build_win32ide\bin\Release\RawrXD-Win32IDE-Native.exe
RUN_UTC=2026-11-11T19:32:06Z
OPERATOR=collab_finish_sole_owner
STATUS=PARTIAL_RUNTIME_REACHED_UNPROMOTED
SHA_BOUND=1
COLLAB=SOURCE_WIRED
P06=RUNTIME_REACHED_UNPROMOTED (5610 OBSERVED_OUTPUT / 5611 SHRINK / 5612 POSTED)
P07=FAIL
P07_HWND_VIS=FAIL t0=True t1=False t2=False t3=False allPresent=True anyPaneVis=True
P07_EVIDENCE=RUNTIME_EVIDENCE/GUI_FOLLOWUP_RECEIPT.txt
P07_RUNLOG=RUNTIME_EVIDENCE/gui_followup_20261111-143139.txt
P08=FAIL
P09=FAIL
P11=FAIL
PRODUCT_RUNTIME_PASS=0/6
HOTPATCH_TIP_BIND=HASH_OK_LIVE_TIP run=20261111_143251
CERTIFIED=0
PROMOTE=0
TIP_CLIMB=HOLD
NOTE=Collab wired on tip; exclusive pane vis still FAIL — no invent PASS
```
