#pragma once
/* Causal SPIN — time is read-only; causality is write-only. */
#define RAWRXD_CAUSAL_TIME_001 1
#define RAWRXD_EOM_SPIN_001 1
#define TIME_IS_NOT_A_VARIABLE 1
#define TIME_IS_DEPENDENCY_CLOSURE 1
#define TOKEN_TIME_CANNOT_BE_WRITTEN 1
#define TOKEN_TIME_CAN_ONLY_BE_MEASURED 1
#define CAUSALITY_IS_WRITE_ONLY 1
#define TIME_IS_READ_ONLY 1
#define SPIN_OPEN_ON_TOKEN 1
#define SPIN_WHILE_REQUIRED_REQUESTS_EXIST 1
#define SPIN_STOP_ON_DEPENDENCY_CLOSURE 1
#define TOKEN_CLOSE_ON_SPIN_STOP 1
#define TOKEN_EMIT_AFTER_CLOSE 1
#define WORK_COMPLETED_NE_TOKEN_TIME 1
#define DISPATCH_IS_CAUSAL_WRITE 1
#define SPIN_CLOSE_IS_TEMPORAL_READ 1
/*
  TOKEN_TIME = T(SPIN_CLOSE) - T(SPIN_OPEN)
  SPINNING   = unresolved_required_dependencies > 0
  TPS        = CLOSED_SPINS / WALL_SECOND

  Never write target_t into the loop. Shallow the dependency graph
  until measured spin lifetime closes within budget.
*/
