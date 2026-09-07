# P1_REGENERATIVE_RUNTIME_001

**Status:** SMOKE-READY  
**Hard law:** `PATCH_HISTORY_IS_NOT_RUNTIME_AUTHORITY = REQUIRED`

## Inversion

```text
DON'T MAINTAIN THE MACHINE.
MAINTAIN THE LAWS THAT CAN GENERATE THE MACHINE.

DON'T REPAIR THE RUNTIME.
RECREATE THE SMALLEST RUNTIME THAT REALITY CURRENTLY REQUIRES.

DON'T PRESERVE OPTIMIZATION HISTORY.
PRESERVE PROOF, THEN RE-SYNTHESIZE FROM ZERO.
```

## Generation function

```text
I_{G+1} = F(SealedAuthority, HardwareFacts, WorkloadFacts, Budgets, RetainedProofs_G)

∂I_{G+1} / ∂PatchHistory_G = 0
```

## Gates

```text
ACTIVE_RUNTIME_IMMUTABLE             PASS
NEXT_RUNTIME_BUILT_PRIVATELY         PASS
NEXT_RUNTIME_DERIVED_FROM_FACTS      PASS
OLD_PATCH_HISTORY_NOT_REQUIRED       PASS
MAINTENANCE_OPERATION_ELIDED         PASS
REGEN_COST_ACCOUNTED                 PASS
REGEN_CHEAPER_THAN_MAINTENANCE       PASS
OUTPUT_EQUIVALENCE                   PASS
AUTHORITY_UNCHANGED                  PASS
RESOURCE_CAPS                        PASS
ATOMIC_GENERATION_SWAP               PASS
OLD_RUNTIME_RETIRED_AFTER_READERS    PASS
```

## Lifetime bias

```text
Sealed → Session → Generation → Token → Ephemeral
STATE_LIFETIME = minimum required for correctness
```

## Discard gate

Ephemeral hotpatch slots are laboratory benches only.  
On PHYSICAL_HOTPATCH PASS → translate into RetainedProof → zero slots.

## Sources

```text
src/deep2/regenerative/*
src/deep2/regenerative/generation_authority_record.asm
tests/regenerative_runtime_smoke.cpp
```

## Example (smoke)

```text
G91 overloaded → proofs retained
REGENERATE G92 from facts (not Mutate(G91))
GPU split + prefetch N+2 + justified rules only
atomic swap → G91 retired
```
