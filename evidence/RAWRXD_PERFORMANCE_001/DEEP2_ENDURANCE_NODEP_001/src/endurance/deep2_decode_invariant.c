/* deep2_decode_invariant.c — reconcile before next token; no PASS minting */
#include "deep2_decode_invariant.h"
#include <string.h>
void d2_inv_init(D2Inv *i, uint64_t seq, uint64_t epoch)
{
    memset(i, 0, sizeof *i);
    i->seq_id = seq; i->epoch = epoch;
}
int d2_inv_begin_fwd(D2Inv *i, uint64_t pos, uint64_t sealed)
{
    if (!i) return 0;
    if (sealed) { i->fail = "SEALED_LOGITS_REUSE"; i->sealed_reuse++; return 0; }
    if (i->fwd && pos != i->last_pos + 1ull && !(i->fwd == 0)) {
        /* first token may be 0 */
    }
    if (i->gen && pos + 1ull != i->gen + 1ull && pos != i->gen) {
        if (pos < i->last_pos) { i->fail = "TOKEN_POSITION_REGRESS"; return 0; }
    }
    if (i->expect_commit || i->expect_adv) {
        i->fail = "PRIOR_TOKEN_UNRECONCILED"; return 0;
    }
    i->fwd++; i->last_pos = pos; i->expect_commit = 1;
    return 1;
}
int d2_inv_end_fwd(D2Inv *i, uint64_t full_block_ok)
{
    if (!i || !full_block_ok) { if (i) i->fail = "FULL_BLOCK_FORWARD_FAIL"; return 0; }
    i->full_block++;
    return 1;
}
int d2_inv_commit(D2Inv *i, uint64_t pos)
{
    if (!i || !i->expect_commit) { if (i) i->fail = "COMMIT_WITHOUT_FORWARD"; return 0; }
    if (pos != i->last_pos) { i->fail = "COMMIT_POS_MISMATCH"; return 0; }
    i->commit++; i->expect_commit = 0; i->expect_adv = 1;
    return 1;
}
int d2_inv_advance(D2Inv *i, uint64_t next_pos)
{
    if (!i || !i->expect_adv) { if (i) i->fail = "ADVANCE_WITHOUT_COMMIT"; return 0; }
    if (next_pos != i->last_pos + 1ull) { i->fail = "ADVANCE_NOT_MONOTONIC"; return 0; }
    i->adv++; i->gen++; i->expect_adv = 0;
    return 1;
}
int d2_inv_reconcile(const D2Inv *i, uint64_t target)
{
    if (!i || i->fail) return 0;
    if (i->sealed_reuse) return 0;
    if (i->expect_commit || i->expect_adv) return 0;
    if (!(i->fwd == i->full_block && i->full_block == i->commit
          && i->commit == i->adv && i->adv == i->gen)) return 0;
    if (target && i->gen != target) return 0;
    return 1;
}
