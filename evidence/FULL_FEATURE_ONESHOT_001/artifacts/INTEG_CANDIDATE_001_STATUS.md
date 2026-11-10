# INTEG_CANDIDATE_001_STATUS

ASOF_UTC=2026-11-09T17:01:00Z
TIP_PACKAGE=tip_integ_candidate_001
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe
CAND_EXE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe

```
TIP_SHA256=1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE
UNIFIED_PACKAGE_CAND_BUILD=1
PRIOR_SUPERSEDED=F83CA270… / 1AE26B8F… / F006728E… / 401ACC2D… (no PASS inheritance)
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
TIP_MOVE_AUTHORIZED=0
HIDDEN_GAP_AUDIT=SEALED
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Absorbed into this tip (source → rebuild)

| Fix | Evidence |
|-----|----------|
| HWND Build 1604 + EM_REPLACESEL + Problems/VS_UNICODE | Remeasured PASS on this SHA |
| INPUT_EVENT journal strings present in EXE | STR_INPUT_EVENT=PRESENT |
| PowerShellPanelProc install + IDs 5600-band | Prior absorb; panel HWND found |
| AgentStepTimeline: no `[powershell]` chip → chat mirror | AI_TRANSCRIPT_UNTOUCHED=PASS this SHA |
| PS command delivery via WM_COPYDATA (`PSCM`) | Root fix for cross-process empty GetWindowText; `ls` listing PASS |

Sealed packages not overwritten: tip006 / A4F / CC79 / tip_hwnd_repair_001.

## Gate matrix (THIS SHA only)

| Gate | Result | Receipt |
|------|--------|---------|
| P1 Output Build id1604 real cl lines | **PASS** (LEN=990, MSVC_HITS=3, C2065/C2660 sample) | `INTEG_CANDIDATE_001_HWND_RECEIPT.txt` |
| P1 Problems items | **PASS** (peak=3) | same |
| P1 click-to-line | **PASS** (`POSTED_NM_DBLCLK_LINE1`, editor line=1) | same |
| P1 PowerShell `ls` → pane directory listing | **PASS** (342→1421; `Directory:` + Mode/LastWriteTime) | `INTEG_CANDIDATE_001_PS_RECEIPT.txt` |
| P1 PS no `[powershell]` chat leak | **PASS** (CHAT 0→0; tag ABSENT_THIS_RUN) | same |
| P2 Chat Ctrl+Enter + Send one-dispatch journal | **FAIL / NOT_CLOSED** | Full IED harness hung after ENTER journal hit; bounded P2 smoke MAIN_HWND=0 flake. Do not invent PASS. Partial prior runlog: ENTER events=1 on this SHA before hang (`input_event_dispatch_run_20261109-113925.txt`). |
| P2 open/edit/save smoke | **PARTIAL** | Open implied by HWND fixture path (broken_multi.cpp in editor sample). Dedicated edit/save smoke FAIL (launch HWND=0). |
| P2 cancel/recovery | **NOT_REACHABLE** | Stop control not exercised on surviving session this turn. |

```
P1_CONJUNCTION_ON_1046C2B8=PASS
P2_CONJUNCTION_ON_1046C2B8=FAIL_CLOSED
INTEGRATED_P1_P2=FAIL_CLOSED
100_PERCENT=NOT_MET
```

## Root cause closed (PS)

Cross-process `SetWindowTextW` left UI-thread `GetWindowText*` empty on the same HWND (harness verify saw `ls`, execute saw `wlen=0`). Fix: panel `WM_COPYDATA` command path (`dwData=PSCM`) → `writeInput` → `onOutput` → `appendPowerShellOutput`. Measured directory listing in pane.

## Next gap only

**Close P2 Chat input-event one-dispatch on SHA `1046C2B8…` (or replacement SHA if rebuild required):** finish Ctrl+Enter + Send with `INPUT_EVENT` + `CHAT_SEND_*` journal proof bound to session_id/run_id without harness hang; then cancel/recovery + durable edit/save on the same SHA. Do not promote.

## Laws (unchanged)

```
PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0
MATURITY=82_PERCENT_UNCHANGED
ISSUE_49_NOT_CLAIMED=1
INVESTIGATE_NE_CONFIRMED=1
PARTIAL_TIP_PASS_NE_INTEGRATED_PASS=1
```
