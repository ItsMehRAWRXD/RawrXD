# ACCEPTANCE_DISPOSITION_RECONCILE

ASOF_UTC=2026-11-09T18:26:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
NO_CROSS_SHA_PASS_INHERITANCE=1

## Correction vs inbound table

| Gate | Inbound claim | Authoritative now |
|------|---------------|-------------------|
| Artifact directory listing | PASS | PASS |
| Existing P1/P2 receipt discovery | PASS | PASS |
| `1046C2B8` P1/P2 evidence bind | Reported complete | P1 PASS; P2 chat journal PASS |
| `EXACTLY_ONCE` | PASS (previously reported) | PASS@C43B prior scope only; freeze current SHA **NOT_VERIFIED** |
| PowerShell `LS_IN_PANE` | FAIL (incorrect regress on integ) | **PASS_ON_1046C2B8** preserved; **FAIL@35C22** measured; **PASS_ON_430B2108** after PSCM rebuild (controlling freeze) |
| Freeze-001 Native-Ext SHA | Not yet confirmed | **Confirmed** `430B21087018165B898F9B224896CCE3EE1273F10582EFA60E44705E25C4B547` |
| Four-panel coexistence | (requested next) | **FAIL_CLOSED_GAPS** on `430B…` (6/17 PASS) |
| Same-SHA integrated acceptance | NOT DEMONSTRATED | NOT DEMONSTRATED |
| Maturity / PROMOTE / CERTIFIED | 82% / 0 / 0 | Unchanged |

## Dual / triple PowerShell receipts (do not collapse)

| SHA | LS_IN_PANE | Role |
|-----|------------|------|
| 1AE26 / F83CA | FAIL | Historical |
| 1046C2B8 | PASS | Integ candidate P1 |
| 35C22 | FAIL_NO_OUTPUT | Pre-PSCM freeze (invalidated by rebuild) |
| 430B2108 | PASS | Controlling freeze tip after PSCM |

## Next

Remeasure EXACTLY_ONCE + H57 + H21 on `430B2108…` only. Four-panel Problems/debug gaps remain. No invent PASS. PROMOTE=0.
