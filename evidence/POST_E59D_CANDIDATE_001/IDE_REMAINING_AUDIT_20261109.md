# RawrXD IDE — Remaining Work Audit

ASOF_UTC=2026-11-09T06:32:00Z
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
FAIL_CLOSED=NOT_RUN!=PASS
JUDGMENT_PERCENT_NE_PASS=1

## Candidate under audit

```
CANDIDATE_SHA=18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68
CONTROLLING_SHA=55BE19B7… (Finish-25 seal untouched)
REQUEST_A_SURVIVES=1  # harness NO_SB_GETTEXT_CROSSPROC; receipt 20261108-225712
HARNESS_CROSSPROC_SB_GETTEXT=PROVEN_ORIGIN
CANCEL_PRODUCT_DEFECT=NOT_PROVEN
PRODUCT_CRASH_FIX_REQUIRED_FOR_A=0  # for identified harness defect only
```

Authority: `PROGRESSION_FINISH25_001\CANCEL\REQUEST_A_SURVIVAL_RESULT_20261108-225712.txt`
Diag board: `CANCEL\REQUEST_A_DIAG_RETURN_BOARD_7EEE4427.txt`

## Finish-25 gate board (measured vs candidate)

| Gate | Controlling 19/25 | On SHA 18FA04F9… | Next |
|------|-------------------|------------------|------|
| T01–T04 | PASS | assumed prior | hold |
| T05 A→Stop→B | NOT_RUN | NOT_RUN | **P0 run** |
| T06 / T09 | PASS | prior | hold |
| T07 Unicode | FAIL (controlling) | PASS (editor retest) | formal credit after freeze |
| T08 tabs/buffer | FAIL (controlling) | PASS (editor retest) | formal credit after freeze |
| T10 session restore | PASS historically / FAIL on progression | FAIL_SESSION_PRESENT_NOT_RESTORED | **P0 repair+retest** |
| T11–T15 | PASS (T15 model-args residual closed) | hold | T15 E2E optional |
| T16 / T20 | PASS | hold | — |
| T17 File Open | PASS | PASS on 18FA | protect |
| T18 / T19 | BLOCKED on Cancel | unblocked *if* T05 PASS | after T05 |
| T21–T23 | PASS | hold | — |
| T24 installer | NOT_RUN (package candidate only) | outstanding | later |
| T25 certify | CERTIFIED=0 | outstanding | last |

```
EDITOR_RETEST_18FA=T17_PASS T07_PASS T08_PASS T10_FAIL
SHA_MATCH_EXPECTED_323A=False  # retest ran against on-disk 18FA04F9
```

Source: `EDITOR\RETEST_T17_T07_T08_T10_SUMMARY.md`

## Subsystem remaining (IDE daily-use)

| Area | Status | Gap |
|------|--------|-----|
| Chat Request A survive | PASS (harness-repaired) | Confirm no other unsafe cross-proc msgs; T05 still open |
| Cancel A→Stop→B | NOT_RUN | Correlation + stale-response rejection |
| Session hard-kill restore | FAIL on 18FA | Marker present, not restored |
| Unicode / tabs / open | PASS on 18FA | Need same-SHA freeze with T05/T10 |
| Native compile/link/run | Outstanding | Verify builder path on candidate |
| Extension load | Outstanding | Load/smoke only |
| Daily-driver freeze | Outstanding | Known-good EXE + rollback evidence |
| GitHub repair push | LFS blocked | Evidence orphan OK; full repair branch blocked |
| Deep2 / promote tetrad | Outside Finish-25 UI | PROMOTE=0 held |

## Immediate execution order

1. **T05** on `18FA04F9…` with repaired harness (no SB_GETTEXTW cross-proc).
2. **T10** diagnose/fix restore path; retest on same SHA.
3. **Same-SHA regression**: T07 + T08 + T17 (already green on 18FA — reconfirm after T10 tip if any).
4. Native compile/link/run + extension load smoke.
5. Freeze daily-driver candidate + rollback receipt; Finish-25 credit only with independent seals.
6. T18/T19 only after T05 PASS; T24 installer / T25 last.

## Law

```
REQUEST_A_SURVIVES=1 ≠ T05_PASS
HARNESS_DEFECT ≠ PRODUCT_DEFECT (for identified SB_GETTEXTW origin)
EDITOR_PASS_ON_18FA ≠ CONTROLLING_FINISH_25_REWRITE
NOT_RUN ≠ PASS
PROMOTE=0
```
