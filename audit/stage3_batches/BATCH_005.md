# BATCH_005 - Genuine Orphan Deprecation

## Type
Modifying batch.

## Goal
Deprecate only files proven to have no legitimate consumers.

## Hard Preconditions
All checks must be satisfied before deprecation:
1. Include/reference checks show no active consumer.
2. Symbol/call graph checks show no active consumer.
3. Nested-CMake checks show not configuration-activated.
4. Runtime-loading checks show not dynamically loaded.

## Dependencies
1. B001 complete.
2. B004 auxiliary retention complete.
3. B006 decisions complete for Deep2 API/server files, if in candidate set.

## Execution Steps
1. Build candidate list from Stage-2 deprecate-candidate rows.
2. Run proof checks for each candidate.
3. Deprecate only proof-qualified candidates.
4. Run full protected-target gate set.
5. Capture audit delta.

## Gates
1. Configure gate: all relevant matrix rows configure.
2. Compile gate: protected targets compile.
3. Test gate: regression and certification checks pass.
4. Runtime gate: no missing behavior/functionality.
5. Audit delta gate: orphan count and coverage deltas documented.

## Risks
High: accidental removal of latent or dynamically wired functionality.

## Rollback
Restore deprecated files and reverse related build-graph removals.

## Exit Criteria
- Every deprecated file has evidence bundle.
- Protected targets remain stable.
- Audit delta approved.
