# BATCH_006 - Deep2 API/Server Explicit Product Decision

## Type
Decision and optional wiring batch.

## Goal
Apply explicit product ownership decisions for Deep2 API/server files instead of implicit deletion.

## In-Scope Files
- Deep2InferenceEndpoint.cpp
- Deep2InferenceGateway.cpp
- Deep2LocalServer.cpp
- Deep2Integration.cpp
- Deep2APIServer.cpp
- Deep2Discovery.cpp
- Deep2Benchmark.cpp

## Allowed Decisions Per File
1. Promote to production-supported target.
2. Retain as auxiliary path.
3. Deprecate with evidence.

## Dependencies
1. B001 baseline complete.
2. Product owner decision per file recorded.
3. Consumer and runtime intent verified.

## Execution Steps
1. Record per-file ownership decision and rationale.
2. Apply wiring changes only for approved promote/retain outcomes.
3. Validate compile/test/runtime impacts.
4. Capture Deep2 coverage and protected-target deltas.

## Gates
1. Configure gate: affected matrix rows configure.
2. Compile gate: RawrXD-Win32IDE, RawrEngine, Deep2 production path compile.
3. Test gate: API/integration or related tests pass for retained/promoted files.
4. Runtime gate: no product regressions for selected ownership path.
5. Audit delta gate: Deep2 coverage and target-edge changes documented.

## Risks
Medium: ownership ambiguity can create partial integrations.

## Rollback
Revert ownership/wiring commit set and restore prior file status.

## Exit Criteria
- All seven files have explicit product decision records.
- Protected gates pass under chosen decisions.
- Deep2 coverage delta is measurable and approved.
