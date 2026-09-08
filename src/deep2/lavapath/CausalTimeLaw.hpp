#pragma once
/* Causal time: write-only causality, read-only time. */
#include "EomSpinLaw.hpp"
#define RAWRXD_CAUSAL_TIME_001 1
#define RAWRXD_WRITE_READ_001 1
#define TIME_IS_NOT_A_VARIABLE 1
#define TIME_IS_DEPENDENCY_CLOSURE 1
#define TOKEN_TIME_CANNOT_BE_WRITTEN 1
#define TOKEN_TIME_CAN_ONLY_BE_MEASURED 1
#define CAUSALITY_IS_WRITE_ONLY 1
#define TIME_IS_READ_ONLY 1
#define DISPATCH_IS_CAUSAL_WRITE 1
#define SPIN_CLOSE_IS_TEMPORAL_READ 1
#define EMIT_IS_EFFECT_OBSERVATION 1
/*
  WRONG: for (t=0;t<T;t++) do_work(t)   // time as writable coordinate
  RIGHT: DISPATCH(cause_set); await SPIN_CLOSE; OBSERVE(effect)

  WRONG: "Make this fit in 6.67ms"
  RIGHT: "Shallow the dep graph until causality closes ≤6.67ms"

  THE_WRITE_THAT_MADE_TIME_IS_THE_ONLY_CAUSALITY=1
*/
