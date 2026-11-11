# Stage-3 Gated Execution Plan

Date: 2026-08-09

Scope: execution planning only. No source or CMake modifications are included in Stage-3.

## Objective
Transform Stage-1 inventory and Stage-2 decisions into a controlled, measurable migration sequence that can be executed one batch at a time with explicit configure/compile/test/runtime/rollback gates.

## Stage Flow
1. Stage-1: source-target inventory.
2. Stage-2: decision classification.
3. Stage-3: gated execution plan (this artifact set).
4. Stage-4+: execute one batch only after all gates pass.

## Baseline Lock (B001)
Stage-1/Stage-2 baselines frozen for delta comparisons:
- add_executable declarations: 71
- add_library declarations: 13
- targets discovered: 83
- source-target edges: 976
- unique referenced sources: 836
- filesystem sources under src: 6256
- root-CMake-unreferenced sources: 5479
- deep2 cpp files: 114
- deep2 root-CMake referenced: 41
- deep2 CMake-orphans: 73

## Batch Sequence
Execution order is fixed unless blocked by gate failure:
1. B001 Baseline protection (no-change).
2. B002 Deep2 production promotion.
3. B003 Duplicate implementation consolidation.
4. B004 Legitimate auxiliary classification.
5. B005 Genuine orphan deprecation.
6. B006 Deep2 API/server explicit product decision.

## Critical Build Gates (all modification batches)
Each modifying batch (B002-B006) must preserve buildability and behavior for:
- RawrXD-Win32IDE
- RawrEngine
- Deep2 production path
- existing certification targets

## Required Batch Gates
Every batch must pass all gates before merge:
1. Configure gate: CMake configure succeeds for required matrix rows.
2. Compile gate: declared target set compiles.
3. Test gate: mapped tests pass.
4. Runtime gate: no functional regression for protected product paths.
5. Audit delta gate: before/after metrics captured and reviewed.

## Audit Delta Requirements
For each modifying batch, capture and compare:
- before source-target edges vs after
- before target count vs after
- before unique production sources vs after
- before Deep2 coverage vs after

## Configuration Matrix Requirement
Because Stage-1 was static-graph driven, Stage-3 includes a configuration matrix to reduce false orphan classification.

Required matrix dimensions:
- Default
- Vulkan
- ROCm/GPU
- MASM
- Win32IDE
- Production strip ON
- Production strip OFF
- Testing
- Benchmarking

## Artifacts Produced
- stage3_execution_plan.csv
- stage3_batches/BATCH_001.md
- stage3_batches/BATCH_002.md
- stage3_batches/BATCH_003.md
- stage3_batches/BATCH_004.md
- stage3_batches/BATCH_005.md
- stage3_batches/BATCH_006.md
- gates/build_validation_matrix.csv

## Exit Criteria for Stage-3 Completion
Stage-3 is complete when:
1. all six batches are defined with dependencies/gates/rollback,
2. validation matrix is approved,
3. B001 baseline pass is recorded,
4. a single next batch is selected for Stage-4 execution.
