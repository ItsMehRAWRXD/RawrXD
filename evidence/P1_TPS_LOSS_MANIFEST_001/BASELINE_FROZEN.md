# P1_TPS_LOSS_MANIFEST_001 / PHYSICAL_HOTPATCH_001

**Status:** SMOKE-READY / OPEN for runtime binding  
**Additive:** does not reopen K2 G10/G11

## Hard invariants

```text
TOKEN_DEBT           = max(0, CURRENT_MS - TARGET_MS)
DEBT_RATIO           = TOKEN_DEBT / CURRENT_TIME
PHYSICAL_RECOVERY    = TOKEN_DEBT + HOTPATCH_OVERHEAD + SAFETY_MARGIN

HOTPATCH_NET_TIME    = TIME_REMOVED - PATCH_OVERHEAD
PHYSICAL_HOTPATCH    = PASS  iff  HOTPATCH_NET_TIME >= TOKEN_DEBT   (predicted)
                     + measured critical-path reduction gates

11× multiplier       = PRIORITY / PRESSURE ONLY
                     NEVER scales measured physical milliseconds
```

## Asymmetric thrust principle

```text
DO NOT ADD POWER UNTIL LOST THRUST HAS BEEN RECOVERED

EFFECTIVE_THRUST = AVAILABLE_POWER - COUNTER_THRUST
TPS ↑ because THRUST_LOSS ↓, not because POWER ↑
```

## P1_TPS_LOSS_MANIFEST_001 predicates

```text
MEASURED_TPS_PRESENT                  PASS
TPS_TO_TIME_CONVERSION_EXACT          PASS
TOKEN_TIME_DEBT_REAL                  PASS
LOSS_SUM_CRITICAL_PATH_BOUND          PASS
OVERLAP_NOT_DOUBLE_COUNTED            PASS
UNKNOWN_TIME_EXPLICIT                 PASS
LOSS_HAS_MEASUREMENT_SOURCE           PASS
11X_USED_AS_PRIORITY_ONLY             PASS
PHYSICAL_TIME_NOT_ARTIFICIALLY_11X    PASS
ASYMMETRY_MEASURED                    PASS
ADDITIONAL_POWER_NOT_ASSUMED          PASS
CANDIDATES_DERIVED_FROM_LOSSES        PASS
PREDICTION_NOT_PROMOTED_AS_MEASURED   PASS
AFTER_RUN_TIME_REMEASURED             PASS
DEBT_RECOMPUTED                       PASS
OUTPUT_EQUIVALENCE_REQUIRED           PASS
AUTHORITY_UNCHANGED                   PASS
```

## PHYSICAL_HOTPATCH_001 gates

```text
TIME_DEBT_BEFORE          > 0
MEASURED_TIME_REMOVED     > 0
PATCH_OVERHEAD_ACCOUNTED  = PASS
CRITICAL_PATH_REDUCED     = PASS
OUTPUT_EQUIVALENT         = PASS
AUTHORITY_UNCHANGED       = PASS
TIME_DEBT_AFTER           < TIME_DEBT_BEFORE
```

## Sources

```text
src/deep2/time_reversal/*
tests/time_reversal_smoke.cpp
evidence/TIME-REVERSAL-CERTIFICATION-LADDER.md
```

## Loop

```text
TARGET TPS → TARGET TIME → TOKEN DEBT → LOSS GRAPH → ASYMMETRY
→ RANK×11 (priority) → HOTPATCH G+1 → MEASURE → DEBT_NEXT → repeat
```
