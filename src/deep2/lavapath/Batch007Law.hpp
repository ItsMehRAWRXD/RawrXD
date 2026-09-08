#pragma once
/* RAWRXD_E2E_BLOCKERS_105 — Batch 007 = blockers 91–105 */
#include "NoMoreBaselineStubsLaw.hpp"

#define RAWRXD_E2E_BLOCKERS_105 1
#define BATCH_007_BEGIN 91
#define BATCH_007_END 105

/*
  BATCH_001=01-15 … BATCH_007=91-105
  Product progress only inside:
    input → model authority → runtime → token commit → stream → receipt
  Hard lock: tokenizer/detok/chunk/cancel/retry/max-tok/ctx/position/receipt
  claims require the same product command that commits real stream tokens.
*/
