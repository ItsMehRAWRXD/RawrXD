# B002 Gate Close-Out

Date: 2026-08-09

Result: OPEN_PENDING_FINAL_AUDIT

## Changes Made

| File | Change |
|---|---|
| src/runtime/CMakeLists.txt | Added TensorExecutionRouter.cpp to rawrxd_runtime; added RAWRXD_NO_VULKAN compile definition; added rawrxd_predictive_memory_test under BUILD_TESTING |
| src/runtime/TensorExecutionRouter.hpp | Added forward declaration of Memory::PredictiveMemoryManager; added setMemoryManager() and advanceLayer() seam methods |
| src/runtime/TensorExecutionRouter.cpp | Guarded Impl::VulkanCompute behind RAWRXD_NO_VULKAN; added memory manager field; implemented seam; integrated ensureResident/recordCompletion in matmul() |
| src/runtime/tests/predictive_memory_test.cpp | Created - 6-scenario deterministic functional gate test |

## Architecture Boundary Preserved

- TensorExecutionRouter remains tier-agnostic. No placement logic added to it.
- Placement decisions stay inside PredictiveMemoryManager.
- Router uses the predictive-memory seam for ensureResident() / recordCompletion().
- B003 boundary correction validated: execution loop owns predict() / prefetch(); router does not call them in matmul().

## Configure Gate - All PASS

| Configuration | Configure | B001 baseline |
|---|---|---|
| Default | PASS | PASS |
| Vulkan | PASS | PASS |
| ROCm/GPU | PASS | PASS |
| MASM | PASS | PASS |
| Win32IDE | PASS | PASS |
| ProductionStrip_OFF | PASS | PASS |
| ProductionStrip_ON | PASS | PASS |
| Testing | PASS | PASS |
| Benchmarking | PASS | PASS |

## Compile Gate - Targeted Testing PASS

| Target | Result |
|---|---|
| rawrxd_runtime (Testing config) | Build exit 0 |
| rawrxd_predictive_memory_test (Testing config) | Build exit 0 |
| rawrxd_router_pmm_integration_test (Testing config) | Build exit 0 |

## Functional Gate - 6/6 PASS

| Scenario | Result |
|---|---|
| 1: demand residency | PASS |
| 2: prefetch no corruption | PASS |
| 3: cancel speculative | PASS |
| 4: eviction respects pins | PASS |
| 5: deterministic placement | PASS |
| 6: failed transfer rollback | PASS |

## B003 Boundary Validation - PASS

`rawrxd_router_pmm_integration_test` verifies the execution-loop ownership model:
- execution loop performs `predict(layer)` and `prefetch(layer)`
- router performs `ensureResident()` then dispatch then `recordCompletion()`

## Audit Delta (B001 to B002) - All Zero

| Metric | B001 | B002 | Delta |
|---|---|---|---|
| Targets | 83 | 83 | 0 |
| Source-target edges | 976 | 976 | 0 |
| Unique referenced sources | 836 | 836 | 0 |
| Win32IDE sources | 595 | 595 | 0 |
| RawrEngine sources | 37 | 37 | 0 |
| Deep2 production sources | 14 | 14 | 0 |
| Deep2 total | 114 | 114 | 0 |
| Deep2 referenced | 41 | 41 | 0 |
| Deep2 orphaned | 73 | 73 | 0 |

Attribution: all zeros expected. B002 changes live in src/runtime/CMakeLists.txt
(subdirectory). Root-CMake static parser already sees rawrxd_runtime via the
conditional add_subdirectory(src/runtime) present before B002. B002 augments
rawrxd_runtime without touching root CMakeLists or protected target composition.

## Allowlist Validation - PASS

Zero out-of-scope files. All changed files match B002_scope_allowlist.csv.

## Protected Targets - NOT YET VERIFIED (Operational)

Operational build checks executed in the Testing build tree produced failures.
The same requested target alias (`RawrXD-Win32IDE`) was also checked in the Win32IDE tree and is not present there either.

Qt6/SoloIDE classification:
- STATUS: OPTIONAL / OUT OF SCOPE for pure-native validation.
- IMPACT: NONE on native runtime validation (`rawrxd_runtime`, `RawrEngine`, `Deep2_*`, `witness_system_test`, `nevm_determinism_validation`, `VAL038_*`).
- Note: `[SoloIDE] Qt6 not found - SoloIDE target skipped` is informational and is not counted as a native-source gate failure.

Observed failures:
- `RawrXD-Win32IDE`: FAIL (target name not present as requested in this tree)
- `RawrEngine`: FAIL (compile errors in `src/deep2/UniversalModelLoader.cpp`)
- `Deep2_Production_Bench`: FAIL (multiple compile failures in deep2 sources)
- `VAL038_Validation_Benchmark`: FAIL (missing `lib/TreeAttention_Fused_VAL038_Debug.lib`)
- `witness_system_test`: FAIL (compile errors in `src/validation/witness_system_test.cpp`)
- `nevm_determinism_validation`: FAIL (compile errors in `src/nevm/*.cpp`)

Evidence file: `audit/gates/B002_protected_build_results.json`.

Attribution rule: these are repository/baseline infrastructure blockers unless proven regression-linked to B002 runtime-seam edits.

Conclusion: static graph invariance is still PASS, but protected-target buildability is not currently proven operationally in this build tree.

## Router Diff Audit

`TensorExecutionRouter.cpp` and `TensorExecutionRouter.hpp` were reviewed via working-tree diff.

Audit outcome:
- Vulkan dispatch path remains present and still gated by backend readiness checks.
- Telemetry counters (`vulkan_count`, `fallback_count`) and reset behavior remain present.
- Initialization/fallback behavior in `InitializeVulkan()` remains intact.
- No explicit synchronization or buffer-management logic was removed (none existed beyond existing Vulkan buffer handles in this unit).
- Primary remaining architectural risk is pointer-derived TensorId lifecycle assumptions.

Commit-range command `git diff 493215699^..HEAD -- src/runtime/TensorExecutionRouter.cpp src/runtime/TensorExecutionRouter.hpp` returned no output for these files in this local state; working-tree diff contains the effective B002 changes.

## TensorId Contract Check

Current B002 seam derives `TensorId` from `reinterpret_cast<uintptr_t>(weight.host_ptr)`.

Findings:
- `PredictiveMemoryManager` exposes `registerTensor(TensorId, bytes)` but no canonical mapper from runtime tensor handles to stable IDs.
- A dedicated canonical-ID source is not currently present in the predictive-memory API surface.

Disposition: pointer-derived IDs are acceptable only as temporary integration identifiers; promote to canonical mapping in a follow-on gate before B003 hard close.

## Disposition Snapshot

| Area | Result |
|---|---|
| Implementation | PASS |
| Deterministic functional test | PASS (6/6) |
| Configure matrix | PASS (9/9 configure) |
| Targeted runtime/test compile | PASS |
| Stage-1 graph invariants | PASS (zero delta) |
| Allowlist | PASS |
| Protected-target operational gate | FAIL / BLOCKED |
| Canonical TensorId contract | OPEN |
| Overall | OPEN_PENDING_FINAL_AUDIT |

## Next Step

Keep B002 as OPEN_PENDING_FINAL_AUDIT until:
1. Protected target buildability evidence is green for the contract-defined target set.
2. Pointer-derived TensorId contract is explicitly ratified or replaced by canonical IDs.
3. B003 boundary ownership remains enforced by runtime integration testing.

After those pass, promote B002 to CLOSED PASS and proceed to B003.
