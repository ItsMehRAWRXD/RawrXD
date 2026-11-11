# B002 Execution Contract

Date: 2026-08-09

Objective: execute B002 as a bounded implementation batch with hard gate checks against B001 baseline.

## Baseline Lock (Before State)
Source: [audit/baseline/B002_before_metrics.json](audit/baseline/B002_before_metrics.json)

- targets: 83
- source-target edges: 976
- unique referenced sources: 836
- Deep2 referenced: 41
- Deep2 orphaned: 73
- Win32IDE sources: 595
- RawrEngine sources: 37
- Deep2 production sources: 14

## Scope Enforcement
Allowed-change scope is strictly defined by [audit/gates/B002_scope_allowlist.csv](audit/gates/B002_scope_allowlist.csv).

Out-of-scope examples:
- broad runtime subsystem rewrites outside listed files
- unrelated deep2 server/api ownership changes (handled by B006)
- cross-cutting refactors not required for predictive placement behavior

## Architecture Boundary (must be preserved)
ExecutionGraph -> PredictiveMemoryManager -> (WorkingSetPredictor, CapacityManager, ResidencyTracker, TensorPlacementManager, TransferScheduler) -> TransferExecutor -> VRAM/RAM/SSD.

Acceptance boundary:
- TensorExecutionRouter remains tier-agnostic.
- Memory-tier decisions remain encapsulated in predictive memory subsystem interfaces.

## Protected Targets
- RawrXD-Win32IDE
- RawrEngine
- Deep2 production path
- VAL038_Validation_Benchmark
- witness_system_test
- nevm_determinism_validation

## Gate Requirements
1. Configure gate:
   - Required config rows remain PASS: Default, Vulkan, ROCm/GPU, MASM, Win32IDE, Production strip OFF/ON, Testing, Benchmarking.
2. Compile gate:
   - All affected protected targets build successfully.
3. Test gate:
   - Existing certification/regression tests stay green.
4. Runtime gate:
   - Predictive-memory path demonstrates functional placement/residency behavior.
5. Audit delta gate:
   - Stage-1 matrix regenerated and compared against B001 baseline.

## Pass/Fail Rules
- PASS only if all protected gates pass and scope remains within allowlist.
- FAIL if any protected target regresses or changes exceed allowlist boundary.

## Rollback Rule
If B002 fails any protected gate:
1. Revert B002 commits only.
2. Re-run baseline protected target checks.
3. Record failure root cause and revise B002 scope.

## Required B002 Output Artifacts
- B002 gate run log (configure/compile/test/runtime outcomes by configuration)
- B002 audit delta comparison (before/after metrics)
- explicit changed-file list validated against allowlist
