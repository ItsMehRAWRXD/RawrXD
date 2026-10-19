#include "bs_policy.h"
int bs_counter_parity(const BsState*s,uint64_t target){return s->forward_calls==target&&s->full_block_calls==target&&s->commit_calls==target&&s->advance_calls==target&&s->generated_tokens==target;}
int bs_live_invariants_ok(const BsState*s){return s->vendor_smoke_pass&&s->local_smoke_pass&&s->pid_alive&&!s->cert_binary_touched&&s->merge_deferred&&!s->promote&&!s->sealed_reuse_seen;}
int bs_terminal_target64_observed_pass(const BsState*s){return s->terminal_pass_seen&&!s->terminal_fail_seen&&!s->sealed_reuse_seen&&s->highest_pos>=63&&bs_counter_parity(s,64);}
