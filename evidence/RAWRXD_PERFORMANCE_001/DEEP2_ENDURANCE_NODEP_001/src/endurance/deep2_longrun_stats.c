/* deep2_longrun_stats.c */
#include "deep2_longrun_stats.h"
#include <string.h>
void d2_st_init(D2Stat *s)
{
    memset(s, 0, sizeof *s); s->min_v = ~(uint64_t)0;
}
void d2_st_add(D2Stat *s, uint64_t v)
{
    uint32_t b;
    if (!s) return;
    if (!s->n || v < s->min_v) s->min_v = v;
    if (v > s->max_v) s->max_v = v;
    s->sum += v; s->n++;
    /* log2-ish coarse buckets */
    b = 0; while (b < 7 && v > (1ull << (b * 4 + 8))) b++;
    s->bucket[b]++;
}
