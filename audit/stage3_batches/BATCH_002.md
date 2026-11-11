# BATCH_002 - Deep2 Production Promotion

## Type
Modifying batch.

## Goal
Promote only Deep2 implementations with demonstrated production consumers. Do not auto-promote API/server orphans based only on file naming.

## Scope
- Candidate set limited to Deep2 files with verified production consumer evidence.
- Excludes automatic promotion of:
  - Deep2InferenceEndpoint.cpp
  - Deep2InferenceGateway.cpp
  - Deep2LocalServer.cpp
  - Deep2Integration.cpp
  - Deep2APIServer.cpp
  - Deep2Discovery.cpp
  - Deep2Benchmark.cpp
- Predictive-memory integration remains isolated behind runtime memory interfaces.
- B002 is not permitted to expand into a general runtime refactor.

## Baseline Reference (must be preserved for delta comparison)
Source: `audit/baseline/B002_before_metrics.json`

- targets: 83
- source-target edges: 976
- unique referenced sources: 836
- deep2 referenced: 41
- deep2 orphaned: 73
- Win32IDE sources: 595
- RawrEngine sources: 37
- Deep2 production sources: 14

## File Boundary Enforcement
- Allowed file scope: `audit/gates/B002_scope_allowlist.csv`
- Out-of-scope file edits fail the B002 gate.

## Dependencies
1. B001 baseline lock complete.
2. Consumer evidence documented per file.
3. Target ownership approval for each promotion.

## Execution Steps
1. Build candidate list from Stage-2 promote-candidate Deep2 rows.
2. Verify production consumer evidence (symbol/include/call path).
3. Promote only evidence-backed files into destination target wiring.
4. Re-run configure/compile/tests/runtime checks.
5. Capture audit delta metrics.

## Gates
1. Configure gate: matrix rows impacted by Deep2 path must configure.
2. Compile gate: RawrXD-Win32IDE, RawrEngine, Deep2 production path compile.
3. Test gate: Deep2 and related regression tests pass.
4. Runtime gate: production behavior unchanged except intended promotion coverage, and predictive placement/residency behavior is functionally valid without tier-aware router branching.
5. Audit delta gate: before/after metrics recorded.

## Risks
Medium: target-wiring drift or hidden dependencies.

## Rollback
Revert promotion commit(s) and restore previous target/source wiring.

## Exit Criteria
- Promotion changes merged only for evidence-backed files.
- Protected targets and gates all pass.
- Delta metrics approved.
