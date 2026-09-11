# Prior Work Braid Ledger 001

```text
PRIOR_WORK_DISPOSITION = RECLASSIFY_NOT_DISCARD
PROMOTION_FAIL ≠ IDEA_DEAD
PROMOTION_FAIL = AUTHORITY_DENIED_FOR_NOW
```

## Purpose

Preserve every reverse-engineered idea (Slingshot, Pinball, braid, sbraid, reverse beacon, overlap cuts, historical tips, coverage ranks) as **classified candidate inventory**. Nothing useful is deleted because it failed a promote word.

Authoritative table: `evidence/RAWRXD_PRIOR_WORK_BRAID_LEDGER_001/LEDGER.tsv`  
Seal: `evidence/RAWRXD_PRIOR_WORK_BRAID_LEDGER_001/RECEIPT.txt`

## Survival invariant

```text
FIXED_GRAPH=1
CANONICAL_MODEL_BYTES=1
TRANSIENT_CANDIDATE_BINDINGS=1
NO_DOWNSTREAM_READBACK_UNLESS_NEXT_TRUE_CONSUMER_IS_HOST=1
PARITY=1
PRODUCT_PATH=1
PURITY=1
```

A prior idea may survive as a candidate. It may not rewrite authority or become baseline without endurance under the sealed graph. It may not read GPU state to host just to feed another GPU consumer.

## Classes

| Class | Meaning |
|-------|---------|
| `BRAID_CANDIDATE` | Complex prior idea preserved |
| `SCHEDULER_HINT` | Steers next binding; no authority alone |
| `FAULT_RECOVERY_PATH` | OOM/spill/retry; not TPS authority |
| `TRANSIENT_BINDING_CANDIDATE` | Runtime binding; promote only by wall endurance |
| `COVERAGE_RANK_ONLY` | Search direction |
| `HISTORICAL_SIGNAL` | Past tip; no chase / no reopen |
| `BLOCKED_READBACK_DOWNWARD` | Illegal unless reclassified host-consumer |
| `HOST_CONSUMER_READBACK` | Legal D2H when host owns next step |
| `REJECTED_AUTHORITY_PATH` | Archive; never product authority |
| `DEAD_FOR_STRICT` | Extension/demo; not product decode |

## Slingshot reclassified

```text
OLD_MEANING = optimistic streamer / residency trick / lane jump
NEW_MEANING = transient graph-preserving binding strategy
AUTHORITY = none
DEFAULT = braided candidate, blocked from downstream readback
CAN_PROMOTE = parity + purity + endurance + wall only
```

```text
SLINGSHOT != STREAMER
PREFETCH_BEFORE_CAUSAL_DEMAND=1
FIXED_DESTINATION=1
NO_READBACK=1
NO_NEW_OWNER=1
```

Law header: `src/deep2/lavapath/SlingshotLaw.hpp`

## Pinball reclassified

```text
PINBALL_DATA_MOVEMENT=0
PINBALL_BINDING_SELECTION=1
DATA STAYS; EXECUTION CURSOR MOVES
```

## Readback downward

```text
NEXT_CONSUMER=DEVICE              → READBACK_BLOCKED
NEXT_CONSUMER=HOST_REQUIRED_MATH  → MINIMAL_READBACK_ALLOWED
NEXT_CONSUMER=LOGGING|METRICS     → BLOCKED (metadata/timestamps only)
NEXT_CONSUMER=UNKNOWN             → FAIL_CLOSED
```

Illegal: `GPU → host inspect/repack → GPU`.  
Legal collapse: `Q/K/V → ATTENTION → O_PROJ` on device.

## Braid rule

```text
SAME_MODEL=1 SAME_GRAPH=1 SAME_START_STATE=1 SAME_METRIC_LAW=1
PARITY_REQUIRED=1
READBACK_DOWNWARD_BLOCKED=1
coverage → wall rank → endurance → promote_or_retain
NO_HILL_CLIMB=1
```

## Permanently dead mechanisms (ideas recovered; movement not)

```text
CPU_FULL_TENSOR_RECONSTRUCTION
EAGER_KVA_STAGING
SHADOW_BUFFER_DUPLICATION
PER_TOKEN_THREAD_SPAWN_JOIN
GPU→CPU→GPU INTERMEDIATE ROUNDTRIPS
READBACK_FOR_LOGGING / OWNER_DISCOVERY
```

## Runtime completion layer

`src/runtime/braid/*` — guards and registry only.  
Existing product anchors stay: `K2BraidExecutionPolicy`, `SlingshotLaw`, `ModelStreamerTrace`.
