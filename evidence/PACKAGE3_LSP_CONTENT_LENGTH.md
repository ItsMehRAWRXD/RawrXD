# Package 3 (LSP Content-Length parser) — verification receipt (2026-11-28)

WORKPACKAGES Package 3 flagged the strict LSP `Content-Length` parser as "patched, not
regression-tested." Verified: the parser is implemented in a shared header and a comprehensive
acceptance test exists and PASSES.

- Parser: `src/win32app/lsp_content_length.h` (`rawrxd::ParseLspContentLength`), used by the
  real client at `Win32IDE_LSPClient.cpp:780` (strict: pure decimal, bounded, no trailing
  garbage; reject → frame dropped, explicit stream recovery).
- Test: `src/win32app/lsp_content_length_test.cpp` (commit f27a260822, 16 cases).

## Build & run
```
cl /nologo /std:c++17 /EHsc /I src\win32app src\win32app\lsp_content_length_test.cpp /Fe:bin\lsp_cl_test.exe
=> BUILD_EXIT=0
bin\lsp_cl_test.exe => RESULT: PASS (16/16), RUN_EXIT=0
```

## Coverage (all PASS)
valid(42), empty, alpha, overflow(20 digits), negative, zero, trailing-garbage(123abc),
oversized(268435457), valid-then-header(7), max-ok(268435456), multi-digit(2048), plus-sign,
decimal(5.0), leading-space(7), recover-after-bad(xyz), recover-valid(9).

## State
Package 3: IMPLEMENTED=1 TESTED=1 FUNCTIONALLY_VERIFIED=1 (16/16) — DISPOSITIONED.
The "not regression-tested" gap is closed.

## Note
Peer commit afa3ddabc4 corrected the reliability record to gpt-oss 0/3 (variance 0-3/3),
confirming the reliability result is model-compliance-bound with high variance.