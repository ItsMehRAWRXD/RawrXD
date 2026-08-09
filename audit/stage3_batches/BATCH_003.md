# BATCH_003 - Duplicate Implementation Consolidation

## Type
Modifying batch.

## Goal
Consolidate duplicate implementation families with canonical-first migration and no premature deprecation.

## Dependencies
1. B001 baseline lock complete.
2. B002 promotions complete (if overlapping families).
3. Canonical implementation approved per duplicate family.

## Required Sequence Per Family
1. Canonical implementation selection.
2. Consumer inventory and mapping.
3. Consumer redirection to canonical implementation.
4. Configure and compile validation.
5. Test and runtime parity validation.
6. Only then deprecate duplicate implementation.

## Scope Rules
- Process one duplicate family at a time.
- No bulk removal in same step as first redirection.

## Gates
1. Configure gate: affected matrix rows configure.
2. Compile gate: protected targets compile.
3. Test gate: family-specific and broad regression tests pass.
4. Runtime gate: canonical behavior matches baseline expectations.
5. Audit delta gate: duplicate-family and target-edge deltas captured.

## Risks
High: hidden consumers and behavior drift.

## Rollback
Revert family-level redirection/deprecation commits; restore prior consumer links.

## Exit Criteria
- Consumer inventory complete for each processed family.
- Runtime parity confirmed before duplicate deprecation.
- Delta metrics approved.
