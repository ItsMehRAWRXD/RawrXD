# RawrXD IDE — Full Remaining-Work Audit

ASOF_UTC=2026-11-09T06:45:00Z
PROMOTE=0
CERTIFIED=0
FAIL_CLOSED=NOT_RUN!=PASS
JUDGMENT_PERCENT_NE_PASS=1
CONTROLLING_FINISH_25_PASS=19
CONTROLLING_SHA=55BE19B7… (untouched)

## A) Candidate under audit

```
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
CANDIDATE_SHA=18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68
SIZE=2509824
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_LINKED_OPTREF
ON_DISK_HASH_VERIFIED=1  # certutil 2026-11-09
ROLLBACK=PROGRESSION_FINISH25_001\CANCEL\logs\RawrXD-Win32IDE-Native.exe.18FA04F9.bak
```

Related SHA eras (do not mix receipts):

| SHA | Role |
|-----|------|
| 55BE19B7… | Controlling Finish-25 seal |
| 3B720981… | POST_E59D baseline era (6,080,512) |
| 323A38A0… | Cited in older `PROGRESSION…\BINARY_HASH.txt` / tip receipts; **≠ on-disk size** |
| 18FA04F9… | **Active daily-use candidate** (this audit; on-disk verified) |
| 049F1068… | Repair slim (T07/T08 FAIL) — historical vs 18FA |
| 7EEE4427… | Accidental 4MB diag rebuild — discard for daily use |
| D9589D9A… | Continuous-loop COMPLETION_020 live cand — **≠** Finish-25 slim 18FA |

```
BINARY_HASH_TXT_MISMATCH=1
# PROGRESSION_FINISH25_001\BINARY_HASH.txt may still list 323A38A0… / 2509312
# ON_DISK_AUTHORITY=REQUEST_A_DIAG_001\BINARY_ON_DISK.md + certutil
DISPOSITION_REFRESHED=1  # REQUEST_A_DIAG_001\DISPOSITION.md now cites 225712 PASS
EXPLORE_CROSSCHECK=9632b35f-a3dc-4e75-9fae-3dec415523ee
```

## B) Request A / Cancel

```
HARNESS_CROSSPROC_SB_GETTEXT=PROVEN_ORIGIN
PRODUCT_CRASH_FIX_REQUIRED_FOR_IDENTIFIED_DEFECT=0
REQUEST_A_SURVIVES=1
RECEIPT=PROGRESSION_FINISH25_001\CANCEL\REQUEST_A_SURVIVAL_RESULT_20261108-225712.txt
DIAG=REQUEST_A_DIAG_001\HARNESS_CROSSPROC_SB_GETTEXT.md
CANCEL_PRODUCT_DEFECT=NOT_PROVEN
```

Law: `REQUEST_A_SURVIVES=1 ≠ T05_PASS`.

## C) Finish-25 gate board

Controlling arithmetic remains **19/25**. Credits on `18FA` do **not** automatically rewrite the controlling seal.

| Gate | Controlling 19/25 | On `18FA04F9…` | Evidence |
|------|-------------------|----------------|----------|
| T01–T04 | PASS | prior / hold | Phase1 seals |
| **T05** A→Stop→B | **NOT_RUN** | **NOT_RUN** (now unblocked to run) | `CANCEL\PHASE1_T05_A_STOP_B_HOLD.md` |
| T06 / T09 | PASS | prior | Phase2 |
| **T07** Unicode/binary | FAIL (controlling) | **PASS** | `PROGRESSION…\EDITOR\TASK07.md` |
| **T08** tabs/buffer | FAIL (controlling) | **PASS** PRESERVED=10 | `PROGRESSION…\EDITOR\TASK08.md` |
| **T10** hard-kill restore | PASS historically / FAIL progression | **FAIL** session present, not restored | `PROGRESSION…\EDITOR\TASK10.md` |
| T11–T15 | PASS | hold | Phase3; T15 model-args residual closed |
| T16 Build/Test | PASS (3B72 era) | **NOT_RUN on 18FA** | `ACCEPTANCE_MATRIX.md` |
| **T17** File Open | PASS | **PASS** | `PROGRESSION…\EDITOR\RETEST_…SUMMARY.md` |
| **T18** soak | BLOCKED | BLOCKED until T05 | `CANCEL\T18_T19_BLOCKED.md` |
| **T19** memory/handles | BLOCKED | BLOCKED until T05/T18 | same |
| T20–T23 | PASS | hold | Phase4/5 |
| **T24** installer | package candidate only / installer NOT_RUN | outstanding | `PHASE5\T24_*` |
| **T25** CERTIFIED | 0 | 0 | conjunction incomplete |

```
EDITOR_RETEST_18FA=T17_PASS T07_PASS T08_PASS T10_FAIL
SHA_MATCH_VS_323A_EXPECT=False
FINISH_25_REMAINING_CONTROLLING=T05 T07 T08 T18 T19 T25
  # note: T07/T08 green on 18FA awaiting formal credit + freeze
DAILY_USE_OPEN_ON_18FA=T05 T10 compile/ext freeze
```

## D) Product surface audit (daily-use)

| Surface | Wired / Historical | On `18FA` | Gap |
|---------|--------------------|-----------|-----|
| Chat / Ollama stream | RUNTIME historically | Request A survive PASS | T05 cancel/stale reject NOT_RUN |
| Cancel lifecycle | FAIL/BLOCKED historically | Request A no longer crash (harness) | A→Stop→B + stale callback |
| Editor Unicode | FAIL→PASS lineage | PASS | Freeze with same SHA |
| Multi-tab / buffer sync | FAIL→PASS lineage | PASS PRESERVED=10 | Freeze with same SHA |
| File open / diagnostics nav | PASS | PASS | Protect |
| Hard-kill unsaved restore | mixed | **FAIL** | Product restore path |
| Native compile/link/run | PASS on 3B72 (T16) | **NOT_RUN** | Verify on 18FA |
| Extension load/isolation | PASS_6 on Win32IDE cand eras | **NOT_RUN** on slim Native | Smoke on 18FA |
| Agentic / DAP / Sidebar | SOURCE_WIRED (COMPLETION_017–020) | not daily-use blocker | Invent PASS=0 |
| Packaging / installer | T24 package ≠ installer | outstanding | After daily freeze |
| Deep2 / tip promote | SCOREBOARD live; AUTH×4 held | outside UI Finish-25 | PROMOTE=0 |

## E) AUTH / host / promote (still held)

From `WIN32IDE_CONTINUOUS_LOOP_001` / Deep2 law (unchanged):

```
TIP_CLIMB=HOLD
ABSORB=NOT_AUTHORIZED
R28_APPLY=HELD
PromoteReady_EMIT=0
PRODUCT_PASS=0
HOST_STABILITY=was UNVERIFIED (AMD/dump soak) — separate from Finish-25 UI
K2_FULL_GEN=HOST_BLOCKED historically
```

`PROMOTE=0` until AUTH×4 ∧ Finish-25 conjunction ∧ independent coverage.

## F) Two finish lines

### Daily-driver ready (controlled local use)

1. Run **T05** on `18FA` with repaired harness (no cross-proc `SB_GETTEXT*`).
2. Fix + retest **T10** hard-kill restore on same SHA.
3. Reconfirm **T07/T08/T17** after any T10 tip change.
4. Native **compile/link/run** + **extension** smoke on same SHA.
5. Freeze known-good EXE SHA + bak + launch path.

### 100% Finish-25 / certified

1. Formal credit T07/T08 on controlling seal after freeze.
2. T18 soak + T19 handles after T05 PASS.
3. T24 real installer path.
4. T25 CERTIFIED + process AUTH×4 / tip absorb.
5. Host stability / K2 as independent gates — do not invent from UI PASS.

## G) Safe vs not verified

**Reasonable now (controlled):**

- Launch slim Native `18FA04F9…`
- Chat Request A / Ollama stream (survive proven under fixed harness)
- File open, Unicode edit, multi-tab buffer sync (PASS on this SHA)

**Not verified / do not trust yet:**

- Stop/cancel + immediate second request (T05)
- Crash/hard-kill unsaved recovery (T10 FAIL)
- Compile/link/run + extensions on this exact binary
- Soak / memory (T18/T19)
- Installer / CERTIFIED / PROMOTE

## Immediate ordered work

| Pri | Work | Status |
|-----|------|--------|
| P0 | T05 A→Stop→B + stale reject | NOT_RUN |
| P0 | T10 restore fix + retest | FAIL on 18FA |
| P1 | Same-SHA T07/T08/T17 reconfirm | PASS already; reconfirm after T10 |
| P1 | Compile/link/run + ext smoke | NOT_RUN on 18FA |
| P1 | Daily-driver freeze + rollback | Outstanding |
| P2 | T18/T19 soak | BLOCKED on T05 |
| P2 | T24 installer | Outstanding |
| P2 | T25 / PROMOTE | Held |

## Law

```
REQUEST_A_SURVIVES=1 ≠ DAILY_DRIVER_READY
EDITOR_PASS_ON_18FA ≠ CONTROLLING_FINISH_25_REWRITE
HARNESS_DEFECT ≠ PRODUCT_DEFECT (SB_GETTEXT origin only)
NOT_RUN ≠ PASS
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
```

Authority cross-cites:
- `POST_E59D_CANDIDATE_001\IDE_REMAINING_AUDIT_20261109.md`
- `POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md`
- `POST_E59D_CANDIDATE_001\REMAINING_9_BLOCKERS.md`
- `PROGRESSION_FINISH25_001\EDITOR\RETEST_T17_T07_T08_T10_SUMMARY.md`
- `REQUEST_A_DIAG_001\HARNESS_CROSSPROC_SB_GETTEXT.md`
