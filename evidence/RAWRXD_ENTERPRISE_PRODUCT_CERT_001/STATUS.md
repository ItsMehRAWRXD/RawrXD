# RAWRXD_ENTERPRISE_PRODUCT_CERT_001

**Version:** 1.0 · **ASOF:** 2026-11-13T23:29-05:00  
**Objective:** Production-ready fully local AI workstation certification (CLI + Win32 GUI + native inference + autonomous coding + Sunshine).

| Field | Value |
|-------|-------|
| Checklist verified PASS | **0 / 128** |
| Checklist % | **0%** |
| EVIDENCE_PARTIAL | **6** (G01-01..04,G01-06,G01-08 SELF_MEASURE; ≠ PASS) |
| Scoreboard maturity (separate) | CLI **67** · GUI **48** · OVERALL **48** (`VALUATION_SCOREBOARD_CANON`) |
| Release | **HELD** |
| PROMOTE | **0** |
| CERTIFIED | **0** |
| INVENT_PASS | **0** |
| Candidate GIT_SHA | `dde963941aa4b7647f94aafaa390f5e2eed72511` (work/v0-first-divergence; tip GUI 6754616E RO; stale CLI CD84354D) |
| Board absorb | R70 G01 source integrity SELF_MEASURE (`BR_G01_SOURCE_INTEGRITY_R70`) |

## Law
See `LAW.txt`. `NOT_RUN != PASS`. `EVIDENCE_PARTIAL != PASS`. Scoreboard ≠ checklist. Cross-SHA credit forbidden for PASS.

## Matrix
`GATE_MATRIX.csv` — 122 `NOT_RUN` · 6 `EVIDENCE_PARTIAL` · 0 `PASS`.

## Priority blockers (engineering record → checklist)
| Blocker | Maps near | Status |
|---------|-----------|--------|
| Gemma AA4F / tip_land AV | G02 / G06 | B8E5F6E5 TOK=8 SEH=0 EXIT=0 AV_CLOSED=1 RELATED (R75 EXIT_NULL; tip RO) |
| C36 LSP hang | G07 | tip HANG/TIMEOUT RELATED (R73); stage INIT_OK crumb ≠ PASS |
| GPU/ref numerical | G02 / G03 | PRE_O@pos1 FA CLOSED; V_1/ATTN_NORM_1@dim1072 CLOSED maxULP=0 (F0A8018F RELATED) |
| ConPTY / HELP_TERM | G05 / G06 | tip-era stop PASS RELATED (R70); cand PASS RELATED; ≠ CERT PASS |
| Multi-family GUI / qdim084 STREAM | G02 / G04 / G06 | R73/R79: bad_alloc CLOSED on 330ECC; ENTER=0 AV VA=-1 RELATED |
| Offline signed install | G12 | Authenticode ABSENT; CLEAN_VM NOT_RUN |
| Model-selected agent EBT | G05 / G08 | FORCE PASS; MODEL_SELECTED=0; wire SOURCE_WIRED RUNTIME=0 |
| CLI clean rebuild | G01-03 | BUILD_OK=1 EXIT=0 A95A1254… (R75); CLEAN_MACHINE=0 ≠ PASS |
| Win32 GUI same freeze | G01-04 | EVIDENCE_PARTIAL BUILD_OK=0 EXIT=1 EXE=NONE (R76); tip 6754616E RO ≠ PASS |

## Authority scoreboard
`../PRODUCTION_MATURITY_TOP25_001/VALUATION_SCOREBOARD_CANON.txt` — PCT invent forbidden here.

## Next
Independent review of G01 EVIDENCE_PARTIAL cells; close rebuild blockers; dispatch CI for G01-07; keep PASS_COUNT=0 until full schema+REVIEWER.
