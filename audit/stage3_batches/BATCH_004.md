# BATCH_004 - Legitimate Auxiliary Classification

## Type
Classification-focused modifying batch (build graph/doc consistency).

## Goal
Explicitly retain benchmark, certification, experimental, and standalone tooling paths so they are no longer unexplained orphans.

## Dependencies
1. B001 complete.
2. B003 duplicate consolidation not blocking classification.

## Scope
- Auxiliary-only classification updates.
- Preserve production target behavior.

## Execution Steps
1. Identify files/targets intentionally auxiliary.
2. Mark and document retained auxiliary status.
3. Validate auxiliary rows in configuration matrix.
4. Capture orphan-status delta.

## Gates
1. Configure gate: Testing and Benchmarking rows configure.
2. Compile gate: auxiliary and protected targets compile as expected.
3. Test gate: relevant test/cert harnesses pass.
4. Runtime gate: production behavior unchanged.
5. Audit delta gate: unexplained-orphan count reduced and documented.

## Risks
Low to Medium: misclassification can hide active production dependencies.

## Rollback
Revert classification/wiring changes and restore prior status labels.

## Exit Criteria
- Auxiliary inventory explicitly retained.
- No protected-target regression.
- Measurable reduction in unexplained orphan set.
