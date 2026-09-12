/* deep2_tensor_range_guard.c */
#include "deep2_tensor_range_guard.h"
void d2_rg_init(D2RangeGuard *g) { g->ok = 0; g->bad = 0; g->fail = 0; }
int d2_rg_check(D2RangeGuard *g, const D2Range *a, uint64_t off, uint64_t n)
{
    uint64_t end;
    if (!g || !a) return 0;
    end = off + n;
    if (end < off || off < a->off || end > a->off + a->bytes) {
        g->bad++; g->fail = "RANGE_VIOLATION"; return 0;
    }
    g->ok++; return 1;
}
