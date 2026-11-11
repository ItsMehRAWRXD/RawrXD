# PROD_AUDIT_BATCH4_001 — Gates 46–60 disposition

ASOF=2026-11-03
SOURCE=agent Batch4 Deep2 GPU parity (accepted fail-closed)
PROMOTE=0
TIP_CLIMB=HOLD
SOURCE_CHANGES=0
REBUILD=0
CERTIFIED=0

## Controlling blockers

| Gate | Status |
|---:|---|
| 51 Qwen3.6 numerical parity | FAIL |
| 53 Kimi K2 host/GPU token parity | FAIL |
| 50 Strict GPU-only | BLOCKED_CONFLICTING |
| 60 150 TPS | UNVERIFIED_HELD (ineligible until parity + real decode) |

## NEXT_GATE

```text
NEXT_GATE=QWEN36_FIRST_DIVERGENCE_LOCALIZE → FULL_MODEL_LOGIT_PARITY
PARALLEL_OPEN=KIMI_K2_GPU_MOE_BRANCH → HOST_GPU_TOKEN_PARITY
SCHEDULER=SCOREBOARD_SCHEDULER_LIVE=1 (sealed; DO_NOT_REOPEN; LIVE≠PROMOTE)
BATCH4_EXIT=FAIL_CLOSED
```

## Law

`COMPONENT != PRODUCT_PASS` · `SCOREBOARD_SCHEDULER_LIVE != PROMOTE` · `NOT_RUN != PASS`

Sealed certificates under `DEEP2_QWEN36_*`, `KIMI_LAYER39_*`, and `G3_DEEP2_SCOREBOARD_*` are not rewritten by this disposition.
