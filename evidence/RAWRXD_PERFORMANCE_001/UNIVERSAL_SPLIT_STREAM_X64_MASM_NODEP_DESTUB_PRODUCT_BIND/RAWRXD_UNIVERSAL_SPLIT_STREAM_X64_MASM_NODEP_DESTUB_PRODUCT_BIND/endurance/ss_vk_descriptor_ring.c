/* ss_vk_descriptor_ring.c */
#include "ss_vk_descriptor_ring.h"
#include <string.h>
void d2_dr_init(D2Dr *d, uint32_t n)
{
    uint32_t i; memset(d, 0, sizeof *d);
    d->n = n && n <= D2_DR_SLOTS ? n : D2_DR_SLOTS;
    for (i = 0; i < d->n; ++i) d->s[i].set_h = 3000ull + i;
}
int d2_dr_bind(D2Dr *d, uint32_t slot, uint64_t gen)
{
    if (!d || slot >= d->n) return 0;
    if (d->s[slot].busy) { d->fail = "DR_SLOT_BUSY"; return 0; }
    d->s[slot].busy = 1; d->s[slot].gen = gen;
    d->busy_n++; if (d->busy_n > d->peak_busy) d->peak_busy = d->busy_n;
    d->binds++; return 1;
}
int d2_dr_release(D2Dr *d, uint32_t slot, uint64_t gen)
{
    if (!d || slot >= d->n) return 0;
    if (!d->s[slot].busy || d->s[slot].gen != gen) {
        d->fail = "DR_RELEASE_GEN"; return 0;
    }
    d->s[slot].busy = 0; if (d->busy_n) d->busy_n--;
    return 1;
}
int d2_dr_constant_after_warmup(const D2Dr *d)
{
    return d && d->n > 0 && d->peak_busy <= d->n;
}
