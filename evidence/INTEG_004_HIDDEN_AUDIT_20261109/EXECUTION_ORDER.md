# EXECUTION_ORDER — fail-closed sequence

```
ASOF_UTC=2026-11-09T12:50:00Z
AUDIT_ID=INTEG_004_HIDDEN_AUDIT_20261109
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
CONTROLLING_TIP=CC79
A4F_IMMUTABLE=1
ENGINEERING_MATURITY_ESTIMATE=82_PERCENT_UNCHANGED
PRIMARY_MILESTONE=Issue_49_single_SHA_integrated_acceptance
NO_CROSS_SHA_PASS_INHERITANCE=1
NOT_RUN_NE_PASS=1
```

Sequence (do not reorder; do not invent PASS):

```
INTEG_004 reverify
  → reconcile
  → authorize tip (HELD)
  → debugger / four-panel
  → Issue #49 E2E
  → deployment
  → Finish-25
  → certification
```

---

## Phase A — INTEG_004 reverify (**B02 first**)

1. Resolve candidate image identity: sealed `47451F24…` ABSENT vs live `69FE3D92…`.
2. On **one** chosen image, remeasure: Extension (incl. **B20** cleanup), Chat, Terminal, Output, Debug-headless, Problems populate + **actual** editor navigation after click (**B12**).
3. Emit SHA-specific matrix. Failures stay on that SHA only.

```
NEXT_GATE=NEEDS_REVERIFY_ON_CHOSEN_INTEG_IMAGE
NO_REBUILD_SOLELY_TO_REPRODUCE_PROBLEMS_UI=1
```

## Phase B — Reconcile

1. Fold Phase A results into MASTER_REGISTER statuses (upgrade only with SHA FAIL/PASS receipts).
2. Reconcile PR #77–#79 themes against chosen SHA (CONFLICTING ≠ product PASS).
3. Keep A4F untouched. Keep historical Finish-25 19/25 arithmetic immutable.

## Phase C — Authorize tip (**HELD**)

1. **B03**: explicit owner authorization required before CONTROLLING_TIP leaves CC79.
2. Until auth: `TIP_MOVE_AUTHORIZED=0` · `TIP_CLIMB=HOLD`.
3. Candidate Problems PASS never auto-promotes tip.

## Phase D — Debugger / four-panel

1. **B39**: wire/prove native debugger UI on the **authorized** SHA (headless ≠ UI).
2. **B40–B44**: BP / step / inspect / stop.
3. **B45–B47**: Chat+Terminal+Output+Debug simultaneous; no stale HWND.

## Phase E — Issue #49 E2E

1. **I49 / H120 / B52**: clean-clone autonomous edit→build-fail→repair→test→review→commit on one EXE SHA.
2. All #49 receipt keys must be witnessed (no synthetic receipts).
3. This is the decisive maturity milestone; 82% does not move before it.

## Phase F — Deployment

1. **B71–B73**: deterministic Windows release build, clean-machine smoke, provenance=tested SHA.
2. Installer / undeclared-DLL / signed-artifact checks (H98–H105) as required.

## Phase G — Finish-25

1. Re-run all 25 gates on the **same** controlling release SHA.
2. Close residual: T05 · **T07** · **T08** · T18 · T19 · T25 (**B75**).
3. `FINISH25_HISTORICAL_19/25 ≠ CURRENT`; do not invent CURRENT elevation.

## Phase H — Certification

1. **B76** final controlling-SHA acceptance matrix.
2. **B77** explicit promotion authorization only after PromoteReady conjunction.
3. **B78** independent certification → only then consider `CERTIFIED` / `PROMOTE` changes.

```
PROMOTE=0 until Phase H conjunction
CERTIFIED=0 until independent cert
PRODUCT_PASS=0 until Issue #49 + integrated panels on one SHA
```

---

## Immediate action queue (start here)

| Order | ID | Action |
|------:|----|--------|
| 1 | **B02** | Choose/recreate INTEG image; cross-subsystem reverify |
| 2 | **B20** | Fix EXT cleanup / quit on that image |
| 3 | **B12** | Prove Problems click → real navigation |
| 4 | **B03** | Request tip-move auth only after matrix |
| 5 | **B39→B45** | Debugger UI then four-panel |
| 6 | **I49** | Product-final E2E |
| 7 | **B75** | Finish-25 on release SHA |
| 8 | **B77/B78** | Promote/cert held until evidence |

```
EXECUTION_ORDER=SEALED
PARENT_MAY_DISPATCH_PHASE_A=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```
