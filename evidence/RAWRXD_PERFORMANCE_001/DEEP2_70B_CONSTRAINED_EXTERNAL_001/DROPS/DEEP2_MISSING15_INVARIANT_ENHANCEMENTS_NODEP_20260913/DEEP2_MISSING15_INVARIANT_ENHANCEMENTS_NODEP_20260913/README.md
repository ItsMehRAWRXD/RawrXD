# Deep2 Missing-15 invariant enhancements — NODEP

Small dependency-free source drop implementing the current post-Phase-A optimization hierarchy:

`SURVIVABILITY > RESIDENCY > PREDICTION > BALANCE > TPS`

The core is one header with 15 single-line inline mechanisms. It deliberately does **not** bind into the product or claim a live PASS. `selftest.c` proves only source semantics.

## Build

Windows/MSVC:

```bat
build_msvc.bat
```

POSIX C compiler:

```sh
./build_posix.sh
```

Expected:

```text
DEEP2_MISSING15_NODEP_SELFTEST=PASS
TOP15_ENHANCEMENTS=15/15
PRODUCT_BOUND=0
PROMOTE=0
```
