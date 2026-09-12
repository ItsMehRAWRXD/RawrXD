/* deep2_arena_guard.c — overlap + freeze + canary accounting */
#include "deep2_arena_guard.h"
#include <string.h>
#define CAN_LO 0xA11CEu
#define CAN_HI 0xC0FFEEu
void d2_arena_init(D2ArenaGuard *a)
{
    memset(a, 0, sizeof *a);
}
int d2_arena_add(D2ArenaGuard *a, uint64_t base, uint64_t bytes, uint32_t owner)
{
    uint32_t i; D2ArenaSlot *s;
    if (!a || a->n >= D2_ARENA_SLOTS || a->frozen_all) return 0;
    for (i = 0; i < a->n; ++i) {
        uint64_t b0 = a->slot[i].base, e0 = b0 + a->slot[i].bytes;
        uint64_t e1 = base + bytes;
        if (!(e1 <= b0 || base >= e0)) { a->fail = "ARENA_OVERLAP"; return 0; }
    }
    s = &a->slot[a->n++];
    s->base = base; s->bytes = bytes; s->used = 0; s->hwm = 0;
    s->canary_lo = CAN_LO; s->canary_hi = CAN_HI; s->owner = owner;
    return 1;
}
int d2_arena_claim(D2ArenaGuard *a, uint32_t idx, uint64_t off, uint64_t n)
{
    D2ArenaSlot *s; uint64_t end;
    if (!a || idx >= a->n) return 0;
    s = &a->slot[idx];
    if (s->canary_lo != CAN_LO || s->canary_hi != CAN_HI) {
        a->fail = "ARENA_CANARY"; return 0;
    }
    end = off + n;
    if (end < off || end > s->bytes) { a->fail = "ARENA_OOB"; return 0; }
    if (end > s->used) s->used = end;
    if (s->used > s->hwm) s->hwm = s->used;
    return 1;
}
int d2_arena_freeze(D2ArenaGuard *a)
{
    uint32_t i;
    if (!a) return 0;
    a->frozen_all = 1;
    for (i = 0; i < a->n; ++i) a->slot[i].frozen = 1;
    return 1;
}
int d2_arena_note_alloc(D2ArenaGuard *a)
{
    if (!a) return 0;
    if (a->frozen_all) { a->alloc_after_freeze++; a->fail = "ALLOC_AFTER_FREEZE"; return 0; }
    return 1;
}
int d2_arena_check_canaries(const D2ArenaGuard *a)
{
    uint32_t i;
    if (!a) return 0;
    for (i = 0; i < a->n; ++i)
        if (a->slot[i].canary_lo != CAN_LO || a->slot[i].canary_hi != CAN_HI)
            return 0;
    return 1;
}
