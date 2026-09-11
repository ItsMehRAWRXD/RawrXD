# Braid Completion Invariant 001

```text
RAWRXD_BRAID_COMPLETION_LAYER_001 = REQUIRED
NOT_TRASH=1
MISSING_COMPLETION_LAYER=SEALED_LAW
COMPLEXITY_ALLOWED_IN_BRAID=1
AUTHORITY_MUST_STAY_FIXED=1
```

## Authority vs candidate

```text
AUTHORITY = fixed graph + canonical model bytes
CANDIDATE = temporary execution binding
SCHEDULER = may choose candidate
PROMOTION = endurance under invariant only
READBACK = host next-true-consumer only
```

```text
CANONICAL_MODEL_BYTES
        │
FIXED_GRAPH_AUTHORITY
        │
TRANSIENT_CANDIDATE_BINDINGS
        │
BRAID_SCHEDULER
        │
PARITY / PURITY / PRODUCT_PATH / WALL ENDURANCE
        │
PROMOTION_OR_RETAIN_AS_CANDIDATE
```

## Complexity placement

```text
PLANNING_COMPLEXITY = UNRESTRICTED_WHEN_USEFUL
HOT_PATH_COMPLEXITY = MINIMIZED
COMPLEXITY_MUST_RESOLVE_BEFORE_OR_OUTSIDE_CRITICAL_DEPENDENCY
COMPLEX_FEATURES_FORBIDDEN = 0
```

Make the system as complex as necessary to remove artificial movement from the critical path. Preserve every useful mechanism; force every mechanism to declare where it belongs.

## Preserve / recover

| Work | Keep | Block | New role |
|------|------|-------|----------|
| Slingshot | residency/prefetch/slots | ownership churn | fixed residency binding |
| Pinball | stable placement/reuse | bouncing payloads | binding selection |
| .sbraid | GPU-native compressed consume | CPU reconstruct | transient quant binding |
| Reverse beacon | pressure/prefetch feedback | hot-path rebuild | next-epoch binding proposal |
| GPU Q ∥ host KV | true overlap | artificial serial join | legal braid candidate |
| Trace join | binding provenance | readback for instrumentation | write-only attribution |

```text
BRAID_THE_IDEA
NOT_THE_FAILED_MECHANISM
```

## Readback firewall

Every D2H requires producer, consumer, reason. Policy:

| Reason | Decision |
|--------|----------|
| HOST_MATH_REQUIRED | ALLOW |
| HOST_API_BOUNDARY | ALLOW_MINIMAL |
| FINAL_OUTPUT_REQUIRED | ALLOW_MINIMAL |
| DEBUG_ONLY / TRACE_ONLY | BLOCK_PRODUCT_PATH |
| UNKNOWN | FAIL_CLOSED |

```text
NO_READBACK_TO_FEED_DOWNSTREAM_GPU_CONSUMER=1
```

## Promotion gate

```text
RANK_BY=GENERATION_WALL_NS_ASC
TPS=DERIVED
PARITY_REQUIRED=1
ENDURANCE_REQUIRED=1
TIP_CLIMB=HOLD
```

Headers: `src/runtime/braid/BraidPromotionGate.hpp`, `GraphInvariantGuard.hpp`, `ReadbackBoundaryPolicy.hpp`.

## Epochs after sealed SX space

SX 18-config epoch remains sealed. Later finite epochs (quant/kernel/residency/slingshot/…) cover legal space without directional climb. Capability/legality elimination before live measure.
