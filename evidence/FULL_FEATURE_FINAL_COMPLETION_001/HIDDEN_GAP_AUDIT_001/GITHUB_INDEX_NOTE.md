# GITHUB_INDEX_NOTE — HIDDEN_GAP_AUDIT_001

```
ASOF_UTC=2026-11-09T12:45:00Z
REPO=ItsMehRAWRXD/RawrXD
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
MOTD_ACK=1
```

## Law

```
GITHUB_CODE_SEARCH_MISS ≠ LOCAL_ABSENCE
ISSUE_PR_BODY_REFERENCE ≠ INDEXED_CODE_HIT
LOCAL_EVIDENCE_PATH_AUTHORITY=1  # for INTEG_004 / Finish-25 ledgers
```

## Measured GitHub code-search misses (prior inventory)

Authority: `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\GITHUB_PR_ISSUE_INVENTORY.md`

| Query | Result |
|-------|--------|
| `gh search code "INTEG_004" --repo ItsMehRAWRXD/RawrXD` | 0 hits |
| `gh search code "Finish-25" --repo ItsMehRAWRXD/RawrXD` | 0 hits |
| `gh search code "Finish 25" --repo ItsMehRAWRXD/RawrXD` | 0 hits |

Finish-25 **is** referenced in PR #77/#78/#79 **bodies** as historical authority `19/25`, but GitHub **code** search does not index issue/PR markdown bodies as code. That miss is **not** evidence that Finish-25 / INTEG_004 work is absent.

## Local presence (authoritative for this audit)

| Artifact family | Local path | GitHub index |
|-----------------|------------|--------------|
| INTEG_004 Problems + EXT receipts | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\` (`LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md`, `INTEG004_ACCEPTANCE_DISPOSITION.md`, `INTEG004_EXT_REVERIFY_RECEIPT.md`, `candidates\tip_final_integ_004\`) | code-search miss |
| Finish-25 historical 19/25 | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` | body refs only on PRs |
| Finish-25 CURRENT matrices | `FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` · `FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | local-only |
| DAILY_DRIVER GATE_BOARD / A4F | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\GATE_BOARD.md` | local-only |
| ~78-item acceptance register | **ABSENT_LOCALLY** (mentions only; see dedupe matrix) | not located |

## GitHub surfaces that *were* fetched (bodies present)

| Ref | State | Notes |
|-----|-------|-------|
| Issue #49 | OPEN | Product-final E2E scenario + receipt keys |
| Issue #50 | OPEN | Cert ladder 0–10; L0 integration seal pending; L1–L10 blocked/pending |
| Issue #57 | OPEN | 45 unchecked gates (A/B/C ×15) |
| PR #75 | OPEN+DRAFT · MERGEABLE | 37 local adapter tests claimed; 16 native-linker UNEXECUTED |
| PR #76 | OPEN+DRAFT · CONFLICTING | Deep2 consolidation HELD |
| PR #77 | OPEN · CONFLICTING | IDE product path (ConPTY/Problems/Output/four-panel) |
| PR #78 | OPEN · CONFLICTING | AgentSession GUI |
| PR #79 | OPEN · CONFLICTING | ExtensionHost runtime |

URLs: `https://github.com/ItsMehRAWRXD/RawrXD/issues/{49,50,57}` · `https://github.com/ItsMehRAWRXD/RawrXD/pull/{75..79}`

## Disposition

```
INTEG_004_FINISH25_MAY_BE_LOCAL_ONLY=1
SEARCH_MISS_NE_ABSENCE=1
USE_LOCAL_RECEIPTS_FOR_INTEG_FINISH25=1
USE_GH_API_FOR_ISSUE_PR_BODIES=1
NO_INVENTED_PASS_FROM_SEARCH_MISS=1
PROMOTE=0
```
