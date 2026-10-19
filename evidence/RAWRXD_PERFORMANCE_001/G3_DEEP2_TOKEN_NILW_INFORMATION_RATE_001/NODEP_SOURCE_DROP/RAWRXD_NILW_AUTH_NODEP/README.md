# RAWRXD_NILW_AUTH_NODEP

Source-only, no third-party dependencies.

Purpose:
- Encode the sealed NILW authorization law.
- Keep Form A and Form B separate by numerator.
- Keep NILW/performance authority independent from scheduler ownership.
- Enforce NOT_RUN != PASS for every runtime proof.
- Derive PASS only from measured counters.

Definitions:

FORM A:
TOKEN_NILW =
    ACTIVE_CODEC_BPW
  * PHYSICALIZATION_RATIO
  * NEW_INFORMATION_FRACTION
  + OVERHEAD_BITS / TOTAL_LOGICAL_WEIGHTS

FORM B:
TOKEN_NILW =
    ACTIVE_NEW_BPW
  * PHYSICALIZATION_RATIO
  + OVERHEAD_BITS / TOTAL_LOGICAL_WEIGHTS

Never mix ACTIVE_CODEC_BPW and ACTIVE_NEW_BPW numerators.

Hard envelope:
    NEW_PAYLOAD_BYTES_PER_TOKEN <= 100 MB
    TPS >= 10
    GENERATION_INFORMATION_RATE <= 1 GB/s

Independent required proofs:
    ACTIVE_SUBSET_MEASURED
    REUSE_MEASURED
    OVERHEAD_ACCOUNTED
    QUALITY_GATE_PASS
    TOKEN_RATE_PASS
    FULL_MATERIALIZATION=0

This package does not change scheduler authority.
