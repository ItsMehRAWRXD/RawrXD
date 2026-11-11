# PHASE_A_COMPLETE — matrix sealed on reconciled candidate

```text
ASOF_UTC=2026-11-09T13:29:30Z
PHASE_A=COMPLETE_MATRIX_SEALED
PHASE_A_ALL_GATES_PASS=0
PHASE_A_OVERALL=FAIL
RECONCILED_CANDIDATE_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
A4F_IMMUTABLE=1
ENGINEERING_MATURITY_ESTIMATE=82
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Meaning of Phase A complete

Phase A **complete** means the SHA matrix is **sealed for the chosen image** (`27E2263E…`), **not** that every gate passed.

```text
PHASE_A_COMPLETE = MATRIX_SEALED(chosen_SHA)
PHASE_A_COMPLETE ≠ ALL_GATES_PASS
PHASE_A_COMPLETE ≠ TIP_MOVE
PHASE_A_COMPLETE ≠ PROMOTE
```

## Gate table (chosen SHA)

| Gate | Disposition |
|------|-------------|
| Extension | PASS |
| Chat | FAIL |
| Terminal | FAIL |
| Output | PASS |
| Debug-headless | PASS |
| Problems populate | PASS |
| B12 caret nav | FAIL |

## B-ID closure

| ID | Closed? | Disposition |
|----|---------|-------------|
| **B02** | No | **FAIL** (Chat + Terminal + B12) |
| **B20** | **Yes** | **PASS** (FORCE_KILL=0 on `27E2263E…`) |
| **B01** | No | **FAIL** (caret not proved on CC79; item anomaly) |
| **B03** | No | **HELD** / `TIP_MOVE_AUTHORIZED=0` |
| **B12** | No | **FAIL** (POSTED_NM_DBLCLK ≠ caret) |

## Deliverables

- `PHASE_A_SHA_MATRIX_27E2263E.md` / `.json`
- `B02_REVERIFY_RECEIPT.md`
- `B20_EXT_CLEANUP_RECEIPT.md`
- `B01_CC79_PROBLEMS_RECEIPT.md`
- `B03_TIP_MOVE_REQUEST.md`
- Supporting receipts under `receipts/` + `logs/`

```text
NEXT=Phase B reconcile register from sealed matrix; keep tip CC79; no A4F modify
```
