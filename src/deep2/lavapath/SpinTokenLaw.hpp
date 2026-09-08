#pragma once
/* SPIN = token = closed request-dependency cell. Causal time only. */
#include "RawrTimeLaw.hpp"

#define RAWRXD_EOM_SPIN_001 1
#define SPIN_OPEN_ON_TOKEN 1
#define SPIN_WHILE_REQUIRED_REQUESTS_EXIST 1
#define SPIN_STOP_ON_DEPENDENCY_CLOSURE 1
#define TOKEN_CLOSE_ON_SPIN_STOP 1
#define TOKEN_EMIT_AFTER_CLOSE 1
#define WORK_COMPLETED_NE_TOKEN_TIME 1
#define SPIN_TIME_NE_WALL_NS 1
#define TOKEN_TIME_IS_CAUSAL_SPAN 1
#define TOKEN_TIME_CANNOT_BE_WRITTEN 1
#define TOKEN_TIME_CAN_ONLY_BE_MEASURED 1
#define CAUSALITY_IS_WRITE_ONLY 1
#define TIME_IS_READ_ONLY 1
#define DISPATCH_IS_CAUSAL_WRITE 1
#define SPIN_CLOSE_IS_TEMPORAL_READ 1
#define TPS_EQ_CLOSED_SPINS_PER_WALL_SECOND 1
/*
  S_N = SPIN_CLOSE - SPIN_OPEN     (causal span; SpinEpoch)
  W_N = wallClose - wallOpen       (observer only; never schedules)
  unresolved_required_dependencies == 0 → STOP_SPIN → CLOSE → EMIT
  SPIN touches resident active subgraph only
  TPS_real = CLOSED_SPINS / WALL_SECOND
           = BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN  (projection)

  Minimize causal depth per token — not "make milliseconds smaller."
*/
