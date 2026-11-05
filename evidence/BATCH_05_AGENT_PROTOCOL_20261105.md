# Batch 5 — Agent protocol and file-read verification

Date: 2026-11-05
Branch: fix/deep2-multimodel-safety-20261025
STATUS=SOURCE_FIXES_COMMITTED
NATIVE_RUNTIME=NOT_VERIFIED
CI=NOT_VERIFIED
PROMOTE=0
CERTIFIED=0

## Committed repairs

- `9385fb3ca76d3e8c40643ef39298199b074aa65a`: add missing `<filesystem>` and `<vector>` includes to the public agent header.
- `ba428c973ecfcffa3322785d8aba8aae656fe73a`: fail closed on malformed, partial and multiple XML-style model tool-call blocks.
- `ab0166226def7072c9b7cd8b91bc5304c4d43281`: replace fixed-size line-buffer read with `std::getline`.
- `7090f30c23ce06418e5da14c09c7909254ab39a8`: extend portable registry tests.

## Fifteen next verification cases

| ID | Verification | State |
|---|---|---|
| P01 | Valid single tagged tool call | PENDING |
| P02 | Tagged tool call with empty arguments | PENDING |
| P03 | Missing closing tool tag | PENDING |
| P04 | Missing closing args tag | PENDING |
| P05 | Multiple tool tags | PENDING |
| P06 | Multiple args tags | PENDING |
| P07 | Bare args without tool | PENDING |
| P08 | Bare registered tool call | PENDING |
| P09 | Bare unregistered tool | PENDING |
| P10 | Final answer without tool | PENDING |
| P11 | Tool result fed into next generation | PENDING |
| P12 | File read of empty file | PENDING |
| P13 | File read of very long line | PENDING |
| P14 | File read beyond EOF | PENDING |
| P15 | File read with line range limits | PENDING |

These are **test cases**, not fifteen completed blockers. An actual PASS requires executable test output bound to the source commit. No generated receipt has been fabricated.

## Remaining end-to-end scope

The model-originated editFiles mutation path, exact disk readback, tool-result reinjection, Deep2 numerical correctness, GPU inference, native Win32IDE GUI behavior, soak/stress, packaging, and independent certification are still OPEN/NOT_VERIFIED.

## Follow-up

1. Execute portable registry tests through GitHub Actions and record job URLs, logs, and commit.
2. Add an isolated protocol parser test target using the production parser without linking GPU runtime.
3. Audit the actual model-to-editFiles dispatcher and its authorization/receipt contract.
4. Re-run affected integration gates when a compatible Windows runner becomes available.
