# P1_RETAINED_PROOF_TABLE_001 — Trust Boundary

**Status:** SMOKE GATE  
**Rule:** K2 ingestion consumes only images derived from a validated canonical proof blob.

## Predicates

```text
PROOF_TABLE_CANONICAL_ENCODING       = PASS
PROOF_TABLE_HASH_MATCH               = PASS
PROOF_FACT_ENVELOPE_MATCH            = PASS
PATCH_HISTORY_INPUT_ABSENT           = PASS
PATCH_HISTORY_PERTURBATION_HASH_SAME  = PASS
GENERATED_IMAGE_HASH_REPRODUCIBLE     = PASS
PATCH_SLOTS_ZERO_AFTER_COMMIT         = PASS
```

## Crash-safe order

```text
measure patch
→ retain normalized proof (envelope-bound)
→ serialize + hash proof table
→ regenerate candidate RealtimeImage
→ verify image and physical budget
→ atomically activate G+1
→ zero all ephemeral patch slots
```

## Hardenings

1. `GeneratorInputs` has **no** patch-history pointer/callback (structural unreachability).
2. Proofs valid only inside sealed hardware/workload/budget/kernel-ABI envelope; mismatch → invalidate + remeasure.
3. Strongest ∂I/∂PatchHistory=0 test: randomize external hotpatch-history bytes; `RealtimeImage` SHA-256 unchanged.

## Sources

```text
src/deep2/regenerative/RetainedProofSerialize.hpp
src/deep2/regenerative/ProofFactEnvelope.hpp
src/deep2/regenerative/Sha256.hpp
src/deep2/regenerative/RegenerativeRuntime.hpp
tests/retained_proof_table_smoke.cpp
```
