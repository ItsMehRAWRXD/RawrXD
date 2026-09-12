/* ss_vk_lifetime.c — create/destroy parity at sequence teardown */
#include "ss_vk_lifetime.h"
#include <string.h>
void d2_lt_init(D2Lt *L) { memset(L, 0, sizeof *L); }
int d2_lt_create(D2Lt *L, uint64_t h, uint32_t kind, uint64_t epoch)
{
    uint32_t i;
    if (!L || !h || L->n >= D2_LT_MAX) return 0;
    for (i = 0; i < L->n; ++i)
        if (L->e[i].alive && L->e[i].handle == h) {
            L->fail = "LT_DOUBLE_CREATE"; return 0;
        }
    L->e[L->n].handle = h; L->e[L->n].kind = kind;
    L->e[L->n].alive = 1; L->e[L->n].epoch = epoch; L->n++;
    L->creates++;
    return 1;
}
int d2_lt_destroy(D2Lt *L, uint64_t h, uint32_t kind)
{
    uint32_t i;
    if (!L || !h) return 0;
    for (i = 0; i < L->n; ++i) {
        if (L->e[i].alive && L->e[i].handle == h) {
            if (L->e[i].kind != kind) { L->fail = "LT_KIND_MISMATCH"; return 0; }
            L->e[i].alive = 0; L->destroys++;
            return 1;
        }
    }
    L->fail = "LT_DESTROY_UNKNOWN";
    return 0;
}
int d2_lt_alive(const D2Lt *L, uint64_t h)
{
    uint32_t i;
    if (!L) return 0;
    for (i = 0; i < L->n; ++i)
        if (L->e[i].alive && L->e[i].handle == h) return 1;
    return 0;
}
int d2_lt_reconcile(const D2Lt *L)
{
    uint32_t i;
    if (!L || L->fail) return 0;
    if (L->creates != L->destroys) return 0;
    for (i = 0; i < L->n; ++i) if (L->e[i].alive) return 0;
    return 1;
}
