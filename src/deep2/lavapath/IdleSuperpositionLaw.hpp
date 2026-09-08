#pragma once
/* Idle devices compound residency; critical path stays thin. */
#include "BgBmLaw.hpp"

#define RAWRXD_IDLE_SUPERPOSITION_001 1
#define SPIN_CRITICAL_PATH_THIN 1
#define IDLE_DEVICE_BW_COMPOUNDS_FUTURE_RESIDENCY 1
#define TOKEN_CLOSE_REQUIRES_ONLY_CRITICAL_PATH 1
#define BG_PREFETCH_CONTINUES_AFTER_TOKEN_CLOSE 1
#define FASTEST_WHEN_NOT_IN_CRITICAL_PATH 1
#define ADDRESSABLE_STATE_RATE_NE_TOKEN_BW 1
#define COMPOUND_VRAM_LANES_MULTIPLY_RESIDENCY_PROB 1

/*
  CRITICAL_PATH_BW ≤ one active GPU (~640 GB/s)
  COMPOUND_PREFETCH_BW = Σ idle GPU + host staging
  ADDRESSABLE_STATE_RATE ≈ compound_prefetch × fabric_bytes
    (e.g. 32×16 fabric × 64GB host → ~32TB/s class addressability)

  That TB/s is residency probability bandwidth — not bytes moved per token.
  SPIN only resolves already-addressable subgraph → EFFECTIVE_BYTES_CAP_150.
*/
