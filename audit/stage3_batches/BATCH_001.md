# BATCH_001 - Baseline Protection

## Type
No-change baseline batch.

## Goal
Freeze reproducible baseline for configure/build/test/runtime and lock audit metrics before any migration batch.

## Scope
- No source edits.
- No CMake edits.
- No target changes.

## Inputs
- Stage-1 artifacts.
- Stage-2 artifacts.
- current synchronized branch state.

## Required Outputs
1. Confirm baseline metrics:
   - source-target edges: 976
   - targets: 83
   - unique referenced sources: 836
   - deep2 referenced: 41
2. Record reproducible command set for configure/compile/tests/runtime validation.
3. Confirm gate matrix rows and protected targets.

## Gates
1. Configure gate: Default and Win32IDE rows configure successfully.
2. Compile gate: baseline protected targets compile as-is.
3. Test gate: baseline selected tests pass.
4. Runtime gate: baseline behavior snapshots captured.

## Risks
Low. No code movement.

## Rollback
Not required.

## Exit Criteria
- Baseline metrics locked.
- Reproducible command references captured.
- Next batch candidate approved.
