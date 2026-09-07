# Time Reversal / Physical Hotpatch — Certification Ladder

**Status:** OPEN / ADDITIVE (does not reopen K2 G10–G11)  
**Frozen claim boundary:** TPS is emergent from critical-path time removal; never assume promotion.

## Ladder

| Gate | ID | Proves |
|------|-----|--------|
| P1 | `P1_PERF_TELEMETRY_001` | Physical counters real (not decorative) |
| P1 | `P1_EXTENDED_TPS_001` | Rolling windows 1s…30m / session |
| P1 | `P1_TIME_LEDGER_001` | Component sum ≈ wall within tolerance |
| P1 | `P1_TIME_REVERSAL_001` | Target TPS → ms budget → TIME_DEBT |
| P1 | `P1_RESOURCE_REVERSAL_001` | Unused RAM/VRAM/GPU → recoverable μs |
| P1 | `P1_PERF_CAUSALITY_001` | Candidate generation causes measured improvement |
| P1 | `P1_SUSTAINED_PROMOTION_001` | Improvement survives extended window |
| P1 | `PHYSICAL_HOTPATCH_001` | Debt consumed on critical path with gates |
| P1 | `P1_TPS_LOSS_MANIFEST_001` | Live loss map; 11× priority only; unknown explicit |
| P1 | `P1_ASYMMETRIC_THRUST_001` | Critical-path cut without raising power ceiling |
| P1 | `P1_REGENERATIVE_RUNTIME_001` | Immutable image from facts; patch history ≠ authority |

## Core inversions

```text
TARGET_TPS
→ TARGET_MS_PER_TOKEN = 1000 / TPS
→ TIME_DEBT = max(0, CURRENT_MS - TARGET_MS)
→ classify critical path: Essential | Avoidable | Movement | Stall
→ TARGET_MS >= ESSENTIAL_FLOOR  else PHYSICALLY_UNSUPPORTED
→ COUNTER_THRUST map (stalls / imbalance / transfers / sync / recompute)
→ ASYMMETRY: unused parallel capacity on critical path
→ portfolio bids: net = gross - overhead; conf-weighted ≥ 1.15× debt
→ RANK ×11 = priority pressure ONLY
→ PHYSICAL HOTPATCH G+1 (side / drag / anticipatory / forward)
→ measure critical-path disappearance
→ DEBT_NEXT = max(0, MEASURED_MS - TARGET_MS)
→ promote or rollback
```

## Dual ledger invariant

```text
SUM(COMPONENT_WORK_US)  may exceed  TOKEN_WALL_US   (overlap OK)
CRITICAL_PATH_US        ≈           TOKEN_WALL_US   (tol explicit)
SUM(CRITICAL_PATH_LOSS) ≈ TOKEN_TIME_DEBT
UNKNOWN stays UNATTRIBUTED — never silently distributed
```

## Asymmetric thrust principle

```text
DO NOT ADD POWER UNTIL LOST THRUST HAS BEEN RECOVERED
EFFECTIVE_THRUST = AVAILABLE_POWER - COUNTER_THRUST
```

## Sources

```text
src/deep2/time_reversal/*
tests/time_reversal_smoke.cpp
sites/screenpilot.tech/gui/time-reversal-panel.html
evidence/P1_TPS_LOSS_MANIFEST_001/
```
