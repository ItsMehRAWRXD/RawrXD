#pragma once
/* RAWRXD_NO_MORE_BASELINE_STUBS_001 — product ladder binary. */
#define RAWRXD_NO_MORE_BASELINE_STUBS_001 1
#define BASELINE_STUB_RUNTIME_BACKED 1
#define BASELINE_STUB_NOT_PRODUCT_PATH 2
#define BASELINE_STUB_BLOCKER 3
/*
  A baseline stub is illegal in the product ladder unless it has one of:
    1. RUNTIME_BACKED=1  — executes real product path
    2. NOT_PRODUCT_PATH=1 — law / docs / synthetic probe / historical evidence
    3. BLOCKER=1 — names missing runtime piece; prevents product PASS
  Any file/test/gate/receipt with none of these is UNFINISHED.

  Closure path (product only):
    input → model authority → decode → token commit → stream → completion receipt
  Proving a gate can fail does NOT close a blocker.
*/
