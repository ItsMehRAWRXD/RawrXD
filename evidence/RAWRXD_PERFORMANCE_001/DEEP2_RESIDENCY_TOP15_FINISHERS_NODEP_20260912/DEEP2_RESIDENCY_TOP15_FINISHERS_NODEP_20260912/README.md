# DEEP2_RESIDENCY_TOP15_FINISHERS_NODEP_20260912

Dependency-free residency regression/hardening side drop.

This package does **not** reopen or replace the governing live RESIDENCY seal.
It exists only to harden the already-sealed invariants and to prevent future
changes from silently reintroducing per-token device/model/weight/reload churn.

Authority boundary:

- RESIDENCY_SEAL_COMMIT=e80ef647e7
- RESIDENCY_SEALED=1
- AUTHORITY=0
- PROMOTE=0
- CURRENT_GATE=DEEP2_ROOFLINE_LOCALITY_001

The portable selftest is synthetic regression coverage only. It cannot mint
live product authority and cannot rewrite DEEP2_RESIDENCY_001 receipts.

## Build

GCC/Clang:

    cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
       -Iinclude src/d2_residency_finishers.c tests/selftest.c -o selftest
    ./selftest

MSVC x64 Developer Prompt:

    build_msvc.bat

Expected selftest tail:

    DEEP2_RESIDENCY_TOP15_FINISHERS_SELFTEST=PASS
    TOP15_FINISHERS=15/15
    RESIDENCY_SEAL_RETAINED=1
    LIVE_PRODUCT_RUN=NOT_RUN
    PROMOTE=0
    NEXT=DEEP2_ROOFLINE_LOCALITY_001
