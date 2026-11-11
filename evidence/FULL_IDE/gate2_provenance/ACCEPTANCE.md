# Gate 2 producer and admission repair acceptance

Audit base: `843a14c3298ab6aade87fbb597748bd8311f2716`, with pre-existing working changes preserved.

This work closes the reader's primitive-capability contradiction and unknown-required-primitive admission only. It does not certify numerical correctness, GPU dispatch, all quantization formats, or the entire primitive gate.

Acceptance:

1. Required primitives are derived from the produced execution operations, in first-occurrence order with duplicates removed.
2. Available and unimplemented sets are disjoint and their union equals the required set. Availability requires the authoritative admission registry's `available` and `kernelPresent` binding verdict, rather than an enum declaration or a frozen historical boundary string.
3. `firstUnimplementedPrimitive` is cleared when no required binding is missing, and otherwise identifies the first missing required primitive. `runtimeExecutable` reflects complete required bindings for a nonempty graph; it is a primitive-binding statement, not a numerical certificate.
4. Required `MatMulFwd` and unknown non-None primitive values remain unavailable and fail admission. Existing implemented primitive bindings and quantization arithmetic are unchanged.
5. Recomputing capabilities clears stale or contradictory previous capabilities. The reader uses the same capability refresh exercised by the regression tests.
6. Fresh CPU compile/link and positive/negative regression runs pass. Provenance records source and executable hashes plus commands and exit codes. Historical PASS receipts and generated global manifests remain untouched.

Current manifest-consistency C1–C7 run exits 0. It verifies agreement of the current emitters and cited evidence, but cannot prove that each primitive executes or that the executable was compiled from its dynamically reported HEAD.

Gate identities remain distinct: historical `MODEL_GENIE_NATIVE_FORWARD_001` Gate 2 is primitive provenance; `RELEASE_G10`–`RELEASE_G20` are the user-proposed October 13 release roadmap. Historical October 13 Gate 12–20 ledger remains `LEDGER_NOT_LOCATED`.
