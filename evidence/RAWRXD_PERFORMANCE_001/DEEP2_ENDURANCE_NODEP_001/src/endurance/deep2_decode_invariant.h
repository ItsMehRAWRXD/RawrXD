/* deep2_decode_invariant.h — central AR counter / sealed / position ledger */
#ifndef DEEP2_DECODE_INVARIANT_H
#define DEEP2_DECODE_INVARIANT_H
#include <stdint.h>
typedef struct {
    uint64_t seq_id, epoch;
    uint64_t fwd, full_block, commit, adv, gen;
    uint64_t last_pos, sealed_reuse;
    uint32_t expect_commit, expect_adv;
    const char *fail;
} D2Inv;
void d2_inv_init(D2Inv *i, uint64_t seq, uint64_t epoch);
int d2_inv_begin_fwd(D2Inv *i, uint64_t pos, uint64_t sealed);
int d2_inv_end_fwd(D2Inv *i, uint64_t full_block_ok);
int d2_inv_commit(D2Inv *i, uint64_t pos);
int d2_inv_advance(D2Inv *i, uint64_t next_pos);
int d2_inv_reconcile(const D2Inv *i, uint64_t target);
#endif
