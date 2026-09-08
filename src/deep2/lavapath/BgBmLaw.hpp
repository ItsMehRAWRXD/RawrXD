#pragma once
/* BG~BM~: naive TB/s ≠ physical bytes/token. Addressability > fetch. */
#include "SpinTokenLaw.hpp"
#include "TpsPhysicsLaw.hpp"
#include "PowerEnvelope.hpp"

#define RAWRXD_BG_BM_001 1
#define NAIVE_BANDWIDTH_NE_PHYSICAL_BANDWIDTH 1
#define TOKEN_WORK_EQ_RESIDENT_ACTIVE_SUBGRAPH 1
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

/* Physics caps (measurement targets, not writable clocks). */
#define TARGET_TPS_150 150
#define SPIN_BUDGET_NS_150 6667000ull
#define EFFECTIVE_BYTES_CAP_150 4270000000ull /* ~4.27 GB @ ~640 GB/s */

/*
  LAW (canonical):
    TPS = BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN
    SPIN touches resident active subgraph only

  671B = address space, not spin traffic.
  150 @ ~640 GB/s ⇒ EFFECTIVE_BYTES ≲ 4.27 GB/token (measurement target).
*/
