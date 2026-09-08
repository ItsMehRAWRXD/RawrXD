#pragma once
/* BG~BM~ — residency/prefetch; SPIN critical path stays tiny. */
#include "CausalTimeLaw.hpp"
#define RAWRXD_BG_BM_001 1
#define RAWRXD_SIMPLE_MATH_001 1
#define NAIVE_BANDWIDTH_NE_PHYSICAL_BANDWIDTH 1
#define TOKEN_WORK_EQ_RESIDENT_ACTIVE_SUBGRAPH 1
#define MISSING_EXPERT_NE_TOKEN_STALL 1
#define GLOBAL_MODEL_MATERIALIZATION 0
#define KV_FULL_CONTEXT_NE_TOKEN_READ 1
#define REQUIRED_BYTES_FETCHED 0
#define REQUIRED_BYTES_RESOLVED 1
/*
  TPS ≈ BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN
  150 TPS @ 640 GB/s ⇒ EFFECTIVE_BYTES ≲ 4.27 GB/token
  (T_resolve+attention+sample leave ~6.07 ms compute budget)

  Naive ~100 TB/s = full weights×TPS fiction.
  Collapse: SPARSE × WINDOW × RESIDENT × FUNGIBLE × HIDE × COMPRESS

  Multi-GPU: SPIN-critical devices minimize; idle devices compound
  prefetch for N+1/N+2. Idle bandwidth ≠ token bandwidth.

  BG never blocks generation. BM set-membership, not fetch-on-miss.
*/
#define TARGET_TPS_150 150
#define SPIN_BUDGET_NS_150 6667000ull
#define R9700_BW_GBPS 640
#define EFFECTIVE_BYTES_CAP_150 4270000000ull /* ~4.27 GB */
