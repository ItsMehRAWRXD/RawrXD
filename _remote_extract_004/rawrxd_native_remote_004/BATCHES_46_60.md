# RAWRXD_NATIVE_REMOTE_004 — Finalization Batches 46–60

This pass is a closure/hardening pass, not feature expansion.

- B46 CRC32 diagnostic integrity primitive
- B47 packet CRC verification helper
- B48 UTF-16 validation for clipboard/path metadata
- B49 relative-path traversal/absolute-path rejection
- B50 rectangle overflow/bounds validation
- B51 checked 64-bit multiplication
- B52 checked offset/length range validation
- B53 deterministic unique AEAD nonce construction from session salt + sequence
- B54 authentication failure lockout state
- B55 locally-approved permission transition mask
- B56 strict frame ID progression
- B57 tile/frame bounds gate
- B58 explicit secret zeroization
- B59 idempotent close-state transition
- B60 final deterministic primitive self-test

Also corrected the B32 queue ABI bug and B43 rate-limiter timestamp bug discovered during source audit.

## Remaining external certification

No additional feature batch is justified before Windows certification. The remaining work is execution evidence:
1. assemble every TU with ml64;
2. link against the Windows system libraries;
3. run primitive self-tests;
4. run two-process localhost authenticated view test;
5. run two-machine authenticated view test;
6. explicitly approve control on host and verify input;
7. verify view-only rejects input;
8. tamper/replay/malformed packet rejection;
9. disconnect/reconnect/resource cleanup.

Do not emit `RAWRXD_NATIVE_REMOTE_001=PASS` merely because this source archive exists.
