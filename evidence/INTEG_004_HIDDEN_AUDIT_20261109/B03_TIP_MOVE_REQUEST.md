# B03_TIP_MOVE_REQUEST — tip-move authorization request (HELD)

```text
ASOF_UTC=2026-11-09T13:29:00Z
GATE_ID=B03
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
PROPOSED_CANDIDATE=tip_final_integ_004
PROPOSED_CANDIDATE_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
USER_AUTHORIZED=0
OWNER_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
MATURITY=82
```

## Evidence attached (post-B02 matrix)

| Artifact | Role |
|----------|------|
| `PHASE_A_SHA_MATRIX_27E2263E.md` / `.json` | Sealed six-gate matrix on `27E2263E…` |
| `B02_REVERIFY_RECEIPT.md` | Cross-subsystem = **FAIL** (Chat/Terminal/B12 open) |
| `B20_EXT_CLEANUP_RECEIPT.md` | EXT cleanup **PASS** on candidate |
| `B01_CC79_PROBLEMS_RECEIPT.md` | Controlling Problems still **FAIL** full closure |
| `receipts/B12_CARET_NAV_27E2_RECEIPT.txt` | POSTED_NM_DBLCLK ≠ caret |

## Request

Explicit owner/user authorization is **requested** to consider moving CONTROLLING_TIP from CC79 → `27E2263E…` **only after** remaining B02 FAIL gates are closed or explicitly dispositioned.

```text
B03_DISPOSITION=HELD
B03_CLOSED=0
TIP_MOVE_AUTHORIZED=0
ACTION=LEAVE_CONTROLLING_TIP_CC79
```

No tip move performed this turn.
