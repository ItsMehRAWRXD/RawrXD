/* deep2_arena_guard.h — fixed arena HWM + canaries; freeze after warm-up */
#ifndef DEEP2_ARENA_GUARD_H
#define DEEP2_ARENA_GUARD_H
#include <stdint.h>
#define D2_ARENA_SLOTS 32
typedef struct {
    uint64_t base, bytes, used, hwm;
    uint32_t canary_lo, canary_hi;
    uint32_t frozen, owner;
} D2ArenaSlot;
typedef struct {
    D2ArenaSlot slot[D2_ARENA_SLOTS];
    uint32_t n, frozen_all;
    uint64_t alloc_after_freeze;
    const char *fail;
} D2ArenaGuard;
void d2_arena_init(D2ArenaGuard *a);
int d2_arena_add(D2ArenaGuard *a, uint64_t base, uint64_t bytes, uint32_t owner);
int d2_arena_claim(D2ArenaGuard *a, uint32_t idx, uint64_t off, uint64_t n);
int d2_arena_freeze(D2ArenaGuard *a);
int d2_arena_note_alloc(D2ArenaGuard *a); /* fails if frozen */
int d2_arena_check_canaries(const D2ArenaGuard *a);
#endif
