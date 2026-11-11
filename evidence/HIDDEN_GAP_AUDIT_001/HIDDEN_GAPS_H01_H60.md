# HIDDEN_GAPS_H01_H60 — Track C source audit (AUTHORITATIVE)

```
ASOF_UTC=2026-11-09T12:50:00Z
TRACK=C
AUTHORITY=TRACK_C_COMPLETE.md HIGH_SIGNAL + this file
WORKSPACE=F:\rawrxd
MOTD_ACK=1
CONTROLLING_TIP=CC79
CONTROLLING_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
INVENT_CONFIRMED=0
NO_CROSS_SHA_PASS_INHERITANCE=1
VS_UNICODE_OUTPUT=CONFIRMED_PRIOR_NOT_NEW
PHASE_A=PENDING
W3_NOTES=NON_AUTHORITATIVE_FOR_HIGH_SIGNAL (W3 left H21/H42/H43 UNVERIFIED; superseded here)
```

Status: **CONFIRMED** · **CONFIRMED_PRIOR** · **UNVERIFIED** · **INVESTIGATE** · **N_A_OUT_OF_SCOPE**

Law: investigation ≠ defect. `NOT_RUN ≠ PASS`. No cross-SHA inheritance. `47451F24` Problems PASS = RECEIPT_ONLY (EXE ABSENT).

---

## High-signal CONFIRMED (TRACK_C_COMPLETE)

| ID | Status | Evidence |
|----|--------|----------|
| H01 | CONFIRMED | `Win32IDE_Core.cpp` present but ABSENT from `RAWRXD_NATIVE_IDE_SOURCES` (CMakeLists ≈3784–3824); ExtHost TUs only under `RAWRXD_NATIVE_IDE_EXT` |
| H21 | CONFIRMED | `WM_DPICHANGED` only in unlinked `Win32IDE_Core.cpp:963`; ABSENT from linked `Win32IDE_lifecycle.cpp` / other Native TUs |
| H42 | CONFIRMED | PR #75: 37 local adapter claimed PASS + **16 native-linker unexecuted** + Windows PE not certified (`GITHUB_PR_ISSUE_INVENTORY.md`) |
| H43 | CONFIRMED (SHA-split) | tip_ext_host_001 load/activate NOT_RUN; tip_ext_host_002 PASS; slim Native excludes ExtHost unless `-Ext` |
| H51 | CONFIRMED (47451) | `INTEG004_EXT_REVERIFY_RECEIPT.md`: FORCE_KILL=1 → EXT_CLEANUP=FAIL; tip_ext_host_002 FORCE_KILL=0 (no inheritance) |
| H57 | CONFIRMED | `AgentSession` in `rawrxd_agentic_backend` → CLI/tests only; **0** Native/Ext link hits; IDE uses AgenticBridge/LoopBridge |

**CONFIRMED_PRIOR (not newly discovered):** H08, H27 — `VS_UNICODE_OUTPUT` historical CC79 FAIL / INTEG_004 scrub.

---

## 1. Build integrity — H01–H12

| ID | Status | Evidence |
|----|--------|----------|
| H01 | CONFIRMED | Core TU excluded from Native CMake; ExtHost opt-in only |
| H02 | CONFIRMED | Duplicate Problems click: `lifecycle.cpp` linked + Core unlinked; MenuHandlers empty vs `routeCommand` |
| H03 | CONFIRMED | MenuHandlers MinimalInit no-op; headless ExtHost stub OK strings; tip_ext installExtension placeholder lead |
| H04 | CONFIRMED | `RAWRXD_NATIVE_IDE_EXT` default OFF; Qt OFF; Vulkan optional |
| H05 | UNVERIFIED | Clean-rebuild missing-dep concealment not demonstrated |
| H06 | UNVERIFIED | Stale-object false-green not measured |
| H07 | INVESTIGATE | Debug ASan vs Release `/O2` parity unproven |
| H08 | CONFIRMED_PRIOR | VS_UNICODE_OUTPUT inherited env — historical; not new |
| H09 | INVESTIGATE | Optional hardening warn-and-continue |
| H10 | INVESTIGATE | F omits Core vs G historical CMake admits Core; PR76 divergence |
| H11 | UNVERIFIED | Chat route Python generate — fail without Python not demonstrated |
| H12 | UNVERIFIED | Dual-build identical SHA absent |

## 2. Win32 GUI — H13–H26

| ID | Status | Evidence |
|----|--------|----------|
| H13 | INVESTIGATE | MenuHandlers no-op; `routeCommand` default false; invoke-all NOT_RUN |
| H14 | UNVERIFIED | Toolbar E2E ABSENT |
| H15 | UNVERIFIED | Accelerator matrix ABSENT |
| H16 | INVESTIGATE | Stale HWND / Core WM_DESTROY notes; oneshot HWND FAIL receipts; systematic test NOT_RUN |
| H17 | INVESTIGATE | PostMessage marshaling present; direct UI write audit incomplete |
| H18 | UNVERIFIED | PR78 cancel gates NOT_RUN |
| H19 | INVESTIGATE | Modal EnableWindow reentrancy unproven |
| H20 | INVESTIGATE | Focus restore coded; load break NOT_RUN |
| H21 | CONFIRMED | DPI handler only in unlinked Core |
| H22 | CONFIRMED | tip_final_006 OUTPUT_HWND=FAIL id1604 unbound (`OUTPUT_PANEL_GATE.md`); generic resize INVESTIGATE-adjacent |
| H23 | INVESTIGATE | Modal vs background inference NOT_RUN |
| H24 | UNVERIFIED | UI deadlock fault-injection ABSENT |
| H25 | INVESTIGATE | try/catch on agent timer; SEH unproven |
| H26 | UNVERIFIED | Window recreation harness ABSENT |

## 3. Compiler / Problems — H27–H42

| ID | Status | Evidence |
|----|--------|----------|
| H27 | CONFIRMED_PRIOR | Same VS_UNICODE family as H08; not new |
| H28 | UNVERIFIED | Pipe backpressure stress ABSENT |
| H29 | INVESTIGATE | TerminateProcess without JobObject — descendant survival plausible |
| H30 | INVESTIGATE | Timeout without job tree |
| H31 | UNVERIFIED | Spaced-path fixture ABSENT |
| H32 | UNVERIFIED | Unicode diag corruption ABSENT |
| H33 | UNVERIFIED | Warning/error severity oracle ABSENT |
| H34 | UNVERIFIED | Duplicate-burst stress ABSENT |
| H35 | UNVERIFIED | CC79 items=0; 47451 REBUILD_CLEARS_STALE=PASS RECEIPT_ONLY (EXE ABSENT — Phase A) |
| H36 | UNVERIFIED | CC79 NOT_RUN; 47451 CLICK_TO_LINE RECEIPT_ONLY (EXE ABSENT) |
| H37 | UNVERIFIED | Offset oracle ABSENT |
| H38 | UNVERIFIED | Multi-project ownership ABSENT |
| H39 | UNVERIFIED | Linker→Problems ABSENT |
| H40 | INVESTIGATE | AgentSession BuildEvidence not linked into Native (H57) |
| H41 | CONFIRMED | Acceptance hole: PR#75 16 native-linker tests unexecuted (malformed-reloc defect itself UNVERIFIED) |
| H42 | CONFIRMED | Adapter local PASS ≠ native completeness / PE cert |

## 4. ExtensionHost — H43–H56

| ID | Status | Evidence |
|----|--------|----------|
| H43 | CONFIRMED | SHA-split activation; Native excludes ExtHost TUs |
| H44 | UNVERIFIED | Worker IPC handshake proof ABSENT |
| H45 | INVESTIGATE | No length-prefix frame protocol found |
| H46 | INVESTIGATE | Thread-affinity audit ABSENT |
| H47 | UNVERIFIED | Protocol version negotiation ABSENT |
| H48 | INVESTIGATE | Hard-crash isolation NOT_RUN |
| H49 | UNVERIFIED | Callback leak after unload ABSENT |
| H50 | UNVERIFIED | Duplicate subscription detection ABSENT |
| H51 | CONFIRMED | 47451 FORCE_KILL=1 EXT_CLEANUP=FAIL (SHA-scoped) |
| H52 | UNVERIFIED | Crash-restart ABSENT |
| H53 | INVESTIGATE | Ext FS permission gate unproven |
| H54 | UNVERIFIED | Ext UI-block ABSENT |
| H55 | UNVERIFIED | Cross-project corrupt ABSENT |
| H56 | CONFIRMED | Fixture `ext_hello` PASS ≠ real extension matrix |

## 5. AgentSession — H57–H60

| ID | Status | Evidence |
|----|--------|----------|
| H57 | CONFIRMED | AgentSession not in Native link graph |
| H58 | UNVERIFIED | Cancel/orphan PR78 NOT_RUN; Native unlinked |
| H59 | UNVERIFIED | Session fencing ABSENT |
| H60 | UNVERIFIED | Adversarial tool-call parse ABSENT |

---

## Counts (H01–H60)

```
CONFIRMED (daily-driver, excl. PRIOR): H01 H02 H03 H04 H21 H22 H41 H42 H43 H51 H56 H57 = 12
CONFIRMED_PRIOR (not new): H08 H27 = 2
UNVERIFIED: H05 H06 H11 H12 H14 H15 H18 H24 H26 H28 H31-H39 H44 H47 H49 H50 H52 H54 H55 H58-H60
INVESTIGATE: H07 H09 H10 H13 H16 H17 H19 H20 H23 H25 H29 H30 H40 H45 H46 H48 H53
N_A_OUT_OF_SCOPE: 0
PENDING_WORKER: 0
```

```
PROMOTE=0 CERTIFIED=0 PRODUCT_PASS=0
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
ENGINEERING_MATURITY=82
PHASE_A=PENDING
```
