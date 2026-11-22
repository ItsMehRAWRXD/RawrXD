# R25 — Per-Expert Mixed-Precision Allocation

## Receipt

```ini
SOURCE_COMMIT=6a3cc7f4db
EXECUTABLE=build/Release/reap_mixed_precision_plan_test.exe
EXECUTABLE_SHA256=47F909ECEB8644CEB87C85D4008D2577662FE39C152A2C86C2CEB4E39C25F8AD
ALGORITHM=importance_per_incremental_byte_gain
BASELINE_PRECISION=Q2_K
UPGRADE_LADDER=Q2_K_to_Q3_K_to_Q4_K
NEW_EXTERNAL_DEPENDENCIES=0
STUBS=0
EXIT_CODE=0
```

## Acceptance output

```text
PASS mixed precision plan builds
PASS allocation stays within hard budget
PASS one allocation per expert
PASS highest-importance expert reaches Q4_K
PASS second high-importance expert reaches Q4_K
PASS low-importance expert remains at Q2_K
PASS quality objective is measured
PASS allocation is deterministic
PASS budget below Q2 floor rejected
PASS nonfinite importance rejected
PASS empty importance input rejected
PASS_COUNT=11 FAIL_COUNT=0
EXIT=0
```

## Disposition

R25 is implemented and runtime-tested for deterministic per-expert allocation.
The planner is a native policy component; binding its output into physical
multi-shard export and real-model quality calibration remains open under R26–R31.
