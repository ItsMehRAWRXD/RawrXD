# Batch 14 — Agent tool discovery and fail-closed E2E receipts

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Product changes

- `e6f7031759d12bb64a7f1d0b6639f4d67531a109`: normal agent loop now receives the registered tool catalog; empty generation is not accepted as successful final.
- `848bfe5143eac232b78d0411b578a71df82c611c`: add a 15-gate receipt verifier.
- `48d4bc671775c0204a1e12bc3a7a31d071acf54e`: require nonempty evidence files referenced by receipts.
- `7cfdc0129e5c374cc8e9760d0a2649480bcae9f9`: add tests for 15 missing-receipt cases and hash mismatch.

## The 15 required certification gates

1. E2E_01_SOURCE_BUILD
2. E2E_02_CTEST
3. E2E_03_PROTOCOL_PARSER
4. E2E_04_TOOL_CATALOG
5. E2E_05_MODEL_TOOL_CALL
6. E2E_06_MUTATION_AUTHORIZATION
7. E2E_07_EDITFILES_DISK_WRITE
8. E2E_08_EDITFILES_DISK_READBACK
9. E2E_09_TOOL_RESULT_REINJECTION
10. E2E_10_CANCEL_A_STOP_B
11. E2E_11_CRASH_RECOVERY
12. E2E_12_DEEP2_NUMERIC_CORRECTNESS
13. E2E_13_GPU_CORRECTNESS
14. E2E_14_SOAK_AND_PACKAGE
15. E2E_15_INDEPENDENT_CERTIFICATION

The verifier is a **receipt presence/schema/hash/evidence-file** gate, not an independent behavioral proof. It does not execute the native IDE or validate the semantic correctness of evidence. Trusted independent test harnesses must produce the receipts.

## Verification limitations

No CI status or associated workflow run returned for latest commit. No Windows native binary or real GPU runtime is available in this GitHub-only audit. Source changes and tests are committed, but not verified as passing. A complete 100% IDE claim remains unsupported.

## Next

1. Run existing portable parser and registry CI tests and capture job logs.
2. Execute `python tools/test_verify_ide_e2e_receipts.py` in a checked-out repo with tools directory on Python import path.
3. Complete model-originated authorized editFiles tool dispatch and disk readback on a disposable fixture.
4. Execute Windows GUI, Deep2 GPU correctness, soak, packaging, and independent T25 certification gates.
