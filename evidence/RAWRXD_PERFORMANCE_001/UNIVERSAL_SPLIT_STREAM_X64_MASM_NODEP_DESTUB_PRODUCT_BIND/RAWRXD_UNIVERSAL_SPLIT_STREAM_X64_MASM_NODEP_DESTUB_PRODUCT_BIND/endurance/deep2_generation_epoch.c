/* deep2_generation_epoch.c */
#include "deep2_generation_epoch.h"
void d2_ep_init(D2Epoch *e, uint64_t start) { e->epoch = start ? start : 1; e->rejects = 0; }
uint64_t d2_ep_bump(D2Epoch *e) { return ++e->epoch; }
int d2_ep_accept(D2Epoch *e, uint64_t observed)
{
    if (!e || observed != e->epoch) { if (e) e->rejects++; return 0; }
    return 1;
}
