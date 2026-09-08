#pragma once
/* Causal time: write-only causality, read-only time. */
#include "SpinTokenLaw.hpp"

#define RAWRXD_CAUSAL_TIME_001 1
#define RAWRXD_WRITE_READ_001 1
#define TIME_IS_NOT_A_VARIABLE 1
#define TIME_IS_DEPENDENCY_CLOSURE 1
#define THE_WRITE_THAT_MADE_TIME_IS_THE_ONLY_CAUSALITY 1
#define NO_BIDIRECTIONAL_CAUSALITY 1
#define EMIT_IS_EFFECT_OBSERVATION 1

/*
  WRONG: for (t=0;t<T;t++) do_work(t)   // time as writable coordinate
  RIGHT: DISPATCH(cause_set); await SPIN_CLOSE; OBSERVE(effect)

  WRONG: "Make this fit in 6.67ms"
  RIGHT: "Shallow the dep graph until causality closes ≤6.67ms"

  All code is either CAUSAL_WRITE or TEMPORAL_READ — never both.
*/
