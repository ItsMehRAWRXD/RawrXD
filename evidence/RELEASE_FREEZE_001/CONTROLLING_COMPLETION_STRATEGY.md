# CONTROLLING_COMPLETION_STRATEGY — freeze then prove one RC

ASOF_UTC=2026-11-09T14:47:00Z
AUTHORITY=USER_REVISED_APPROACH
ENGINEERING_MATURITY=82%_UNCHANGED_UNTIL_SUBSTANTIAL_ACCEPTANCE_MILESTONE
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
HIDDEN_GAP_AUDIT=SEALED_REFERENCE_ONLY
INVESTIGATION_NE_CONFIRMED=1
NO_ARITHMETIC_18_POINTS=1

## Acceleration order (mandatory)

1. Freeze required release features + acceptance criteria (finite “100%”)
2. Reconcile confirmed blockers → one dependency-ordered list
3. Repair blockers on one candidate branch
4. Build once → full executable SHA
5. Complete native integrated workflow on that SHA
6. Repair failures → retest affected + integrated on replacement SHA
7. Package, clean-machine launch, rollback, seal evidence

## Integrated workflow (must cover)

open/edit/save → compile/link/run → Output and Problems navigation → model response → agent tool action → cancellation and recovery → session persistence → extension shutdown → clean exit
+ repeated-use and failure-recovery checks

## Hidden features — one explicit decision each

- REQUIRED_FOR_RELEASE → expose via working user flow + test
- OPTIONAL → defer explicitly from release scope
- DEPENDENCY_OF_REQUIRED → keep in scope even if invisible

## Law

```
100% = all agreed release gates PASS on final SHA
PROMOTE ≠ CERTIFIED ≠ ENGINEERING_COMPLETE
AUDIT_SEAL ≠ MATURITY_INCREASE
LISTED_INVESTIGATION ≠ CONFIRMED_DEFECT
SMALLEST_REPAIR_SET_UNLOCKING_WORKFLOW > chase_every_Hnn
CC79_RUNTIME_PROGRESS = input to freeze (OUTPUT_HWND PASS on F5F4807E… tip_cc79_integ_002) — not product-final alone
A4F_IMMUTABLE=1
```

## Priority

Smallest set of repairs that unlocks the entire integrated workflow, then packaging and acceptance.
