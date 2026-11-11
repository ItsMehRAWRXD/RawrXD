# B001 Baseline Results

Date: 2026-08-09

Type: non-mutating baseline capture.

Commit baseline: a8e6472c3

## Baseline Statement
This record freezes what RawrXD currently configures/builds before any Stage-4 implementation batch.

## Baseline Metrics
Source: `audit/baseline/source_target_counts.json`.

- targets: 83
- source-target edges: 976
- unique referenced sources: 836
- Win32IDE sources: 595
- RawrEngine sources: 37
- Deep2 production sources: 14
- Deep2 total: 114
- Deep2 referenced: 41
- Deep2 orphaned: 73

## Certification State
Source: `audit/baseline/certification_state.json`.

- certification target count: 3
- certification targets:
  - VAL038_Validation_Benchmark
  - witness_system_test
  - nevm_determinism_validation

## Configuration Matrix (B001)
Source: `audit/baseline/configuration_results.csv`.

| Configuration | Configure | Compile | Tests | Runtime |
|---|---|---|---|---|
| Default | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Vulkan | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| ROCm/GPU | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| MASM | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Win32IDE | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Production strip OFF | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Production strip ON | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Testing | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| Benchmarking | PASS | NOT_RUN | NOT_RUN | NOT_RUN |

Notes:
- B001 intentionally runs configure-only checks.
- Compile/tests/runtime are deliberately recorded as NOT_RUN in this baseline capture.
- Temporary configure folders were created under local temp path and not under source tree.

## Non-Mutating Gate Checks
Source: `audit/baseline/nonmutation_status_compare.json`.

- No source files modified by B001 operations: verified by operation scope (baseline artifact generation only).
- No CMake files modified by B001 operations: verified by operation scope (no CMake edits performed).
- Core Stage-1/Stage-2 artifacts changed: false.
- Target membership changed: false (`target_inventory.csv` hash equals baseline copy hash).
- Visible B001 changes in git status: `?? audit/baseline/`.

## Artifacts Produced
- `audit/baseline/target_inventory.csv`
- `audit/baseline/source_target_counts.json`
- `audit/baseline/configuration_results.csv`
- `audit/baseline/certification_state.json`
- `audit/baseline/nonmutation_status_compare.json`
- `audit/gates/B001_baseline_results.md`

## Outcome
B001 baseline protection is recorded and frozen. Stage-4 can proceed with B002 as the first implementation batch under gated execution.
