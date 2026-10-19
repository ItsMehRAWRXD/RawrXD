#ifndef BS_POLICY_H
#define BS_POLICY_H
#include "bs_common.h"
int bs_counter_parity(const BsState *s, uint64_t target);
int bs_live_invariants_ok(const BsState *s);
int bs_terminal_target64_observed_pass(const BsState *s);
#endif
