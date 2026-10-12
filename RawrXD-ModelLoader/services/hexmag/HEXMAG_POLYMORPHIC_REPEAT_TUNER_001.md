# HEXMAG_POLYMORPHIC_REPEAT_TUNER_001

## Required behavior

HexMag retries are **failure-directed mutations**, not identical reruns.

```text
candidate
  -> verify / reverse / tests
      -> PASS: goal.satisfied -> final
      -> FAIL: classify failure
               -> mutate generation genome
               -> new generation_id
               -> Q_BLOCKING, 3 cyclic passes
               -> generate materially different candidate
               -> repeat
```

## Hard invariants

1. `llm.answer` is a candidate only. Only `llm.final` / `goal.satisfied` may terminate `/ask`.
2. A negative verifier/test/reverse result automatically schedules a retry.
3. Retry `generation_profile.fingerprint` must differ from all previous profiles for the request.
4. Retry `generation_id` must differ. Findings from stale generation IDs are discarded.
5. Tuning is targeted to the failure class:
   - contradiction -> invariant checker
   - counterexample/boundary failure -> boundary explorer
   - unsupported claim/assumption/hallucination -> reverse + assumption breaker
   - test/compile/runtime failure -> test-driven repair
   - stagnation/duplicate -> alternate derivation with more diversity
   - missing information -> evidence guard; do **not** increase creativity to invent facts
6. Retries use `Q_BLOCKING` and `blocking_passes=3`.
7. Tuning is request-local. `persistent_weight_delta_bytes=0`.
8. If retry budget is exhausted, emit `INSUFFICIENT_INFORMATION`; never fake a successful answer.
9. Failure must cause growth and growth must be targeted to the failure.
10. Consensus is not correctness. Distinct failure mechanisms are preferred over repeated copies.

## What “automatically knows it was wrong” means

No generator can detect arbitrary wrongness without a signal. HexMag treats these as authoritative
failure signals:

- verifier finding (`verification.failed`, `contradiction`, `counterexample`, ...)
- compile/test/runtime failure
- reverse/invariant failure
- explicit `/feedback { correct: false, ... }`
- future domain-specific validators

When one of those signals appears, the repeat tuner mutates the next attempt automatically.
