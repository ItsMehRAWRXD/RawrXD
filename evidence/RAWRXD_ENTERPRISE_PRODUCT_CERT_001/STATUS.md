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
| GPU/ref numerical | G02 / G03 | R84 ATTN_PRE_O_0@pos1 OPEN 2.29e-05 C740 host-SDPA RELATED; next FA rebuild holding FFN_DOWN_2 |
| ConPTY / HELP_TERM | G05 / G06 | tip-era stop PASS RELATED (R70); cand PASS RELATED; ≠ CERT PASS |
| Multi-family GUI / qdim084 STREAM | G02 / G04 / G06 | R79 non617F 1EC00779 STREAM_SEH CLOSED DURABLE=1 TOK=2 RELATED≠PASS; tip 6754 RO HOLD |
| Offline signed install | G12 | Authenticode ABSENT; CLEAN_VM NOT_RUN |
| Model-selected agent EBT | G05 / G08 | FORCE PASS; MODEL_SELECTED=0; wire SOURCE_WIRED RUNTIME=0 |
| CLI clean rebuild | G01-03 | BUILD_OK=1 EXIT=0 A95A1254… (R75); CLEAN_MACHINE=0 ≠ PASS |
| Win32 GUI same freeze | G01-04 | EVIDENCE_PARTIAL BUILD_OK=1 EXIT=0 EXE E4B6A937… (R77 private); tip 6754616E RO ≠ PASS |

## Authority scoreboard
`../PRODUCTION_MATURITY_TOP25_001/VALUATION_SCOREBOARD_CANON.txt` — PCT invent forbidden here.

## Next
non617F 1EC00779 private STREAM closed (R79 RELATED); tip AUTH_HOLD; PASS_COUNT=0 · PROMOTE=0.
