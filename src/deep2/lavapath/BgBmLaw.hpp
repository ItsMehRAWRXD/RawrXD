#pragma once
/* BG~BM~ policy authority — residency / sparse / critical-path traffic. */
#include "SpinTokenLaw.hpp"
#include "PowerEnvelope.hpp"

#define RAWRXD_BG_BM_001 1

/* Canonical physics */
#define TPS_EQ_BANDWIDTH_OVER_EFFECTIVE_BYTES 1
/*
  TPS = BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN
  EFFECTIVE_BYTES_PER_TOKEN
    = bytes actually touched by the resident active subgraph

  SPIN optimizes causal distance; BG~BM~ optimizes resident traffic;
  wall time only measures their realization. (RAWR_TIME_001)
*/

/* Runtime law */
#define SPIN_TOUCHES_RESIDENT_ACTIVE_SUBGRAPH_ONLY 1
#define HOST_FULL_MODEL_STREAM 0
#define UNROUTED_EXPERT_TOUCH 0
#define UNRESIDENT_REQUIRED_FETCH_ON_CRITICAL_PATH 0

/* Sparse MoE: model size ≠ token bytes */
#define MODEL_TOTAL_BYTES_NE_TOKEN_BYTES 1
#define TOKEN_WORK_EQ_RESIDENT_ACTIVE_SUBGRAPH 1
/*
  TOKEN_BYTES =
      TOP_K_RESIDENT_EXPERT_BYTES
    + SHARED_REQUIRED_BYTES
    + ACTIVE_KV_BYTES
    + UNAVOIDABLE_OUTPUT_BYTES
*/

/* Optimization arrow (only legal direction) */
#define REDUCE_EFFECTIVE_BYTES_SHORTENS_SPIN 1
#define SHORTEN_SPIN_INCREASES_TPS 1
/*
  reduce EFFECTIVE_BYTES_PER_TOKEN
    → shorten SPIN lifetime
    → increase TPS
*/

#define NAIVE_BANDWIDTH_NE_PHYSICAL_BANDWIDTH 1
#define MISSING_EXPERT_NE_TOKEN_STALL 1
#define PREFETCH_AFFECTS_RESIDENCY_ONLY 1
#define GLOBAL_MODEL_MATERIALIZATION 0
#define KV_FULL_CONTEXT_NE_TOKEN_READ 1
#define REQUIRED_BYTES_FETCHED 0
#define REQUIRED_BYTES_RESOLVED 1
#define TOKEN_TIME_NE_T_FETCH 1
#define TOKEN_TIME_EQ_T_RESOLVE_PLUS_T_COMPUTE 1
#define BG_NEVER_BLOCKS_GENERATION 1
#define BG_PREDICTS_CLASS_NOT_EXACT 1
#define BM_FUNGIBLE_FALLBACK 1
#define HARDWARE_REQUIREMENTS_ARE_ENVELOPE_NOT_CAPACITY 1
#define MODEL_SIZE_NE_SPIN_BYTES 1
#define DISREGARD_HARDWARE_REQUIREMENTS_AS_TPS_GATE 1
#define HOST_SIMD_NE_BG_BM_MECHANISM 1 /* residency/routing; not AVX theater */

/* Performance boundary numbers live in TARGET_150_TPS.txt — not here as seals. */
#define TARGET_TPS_150 150
#define SPIN_BUDGET_NS_150 6667000ull
#define EFFECTIVE_BYTES_CAP_150 4270000000ull /* ~4.27 GB @ ~640 GB/s */
