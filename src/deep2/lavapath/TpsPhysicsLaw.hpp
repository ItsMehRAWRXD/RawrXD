#pragma once
/* Canonical TPS physics — same law as BG~BM~ / SPIN. */
#define RAWRXD_TPS_PHYSICS_001 1
#define TPS_EQ_BANDWIDTH_OVER_EFFECTIVE_BYTES 1
#define SPIN_TOUCHES_RESIDENT_ACTIVE_SUBGRAPH_ONLY 1
#define MODEL_BYTES_NE_SPIN_BYTES 1
#define NAIVE_FULL_WEIGHTS_TIMES_TPS_NE_REQUIRED_BW 1
/*
  TPS = BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN
  SPIN touches resident active subgraph only.

  BANDWIDTH      = critical-path device bus (e.g. ~640 GB/s R9700)
  EFFECTIVE_BYTES = bytes actually touched during one closed SPIN
  Resident active subgraph = routed experts + windowed KV + live kernels
  671B / 120B / full mmap = address space, not SPIN traffic
*/
