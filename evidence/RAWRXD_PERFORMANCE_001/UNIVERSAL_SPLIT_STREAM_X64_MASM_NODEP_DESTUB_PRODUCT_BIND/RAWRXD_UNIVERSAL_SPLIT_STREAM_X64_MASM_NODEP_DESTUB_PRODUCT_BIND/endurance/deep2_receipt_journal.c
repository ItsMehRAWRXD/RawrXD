/* deep2_receipt_journal.c */
#include "deep2_receipt_journal.h"
#include <string.h>
void d2_rj_init(D2Rj *j) { memset(j, 0, sizeof *j); }
int d2_rj_append(D2Rj *j, uint64_t tick, uint64_t pos, uint64_t fwd,
                 uint64_t commit, uint64_t adv, int32_t vr)
{
    D2RjEnt *e;
    if (!j) return 0;
    if (j->n >= D2_RJ_MAX) { j->truncated = 1; return 0; }
    e = &j->e[j->n++];
    e->tick = tick; e->pos = pos; e->fwd = fwd; e->commit = commit;
    e->adv = adv; e->vr = vr; e->flags = 0;
    return 1;
}
