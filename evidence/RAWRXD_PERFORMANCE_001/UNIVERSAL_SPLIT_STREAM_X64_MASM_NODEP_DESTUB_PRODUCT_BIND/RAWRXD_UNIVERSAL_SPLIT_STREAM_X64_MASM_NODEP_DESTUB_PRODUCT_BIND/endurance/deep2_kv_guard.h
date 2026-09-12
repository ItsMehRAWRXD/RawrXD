/* deep2_kv_guard.h — persistent KV bounds + generation */
#ifndef DEEP2_KV_GUARD_H
#define DEEP2_KV_GUARD_H
#include <stdint.h>
#define D2_KV_MAX_LAYER 128
typedef struct {
    uint64_t epoch, gen;
    uint32_t layers, max_pos, cur_pos;
    uint32_t layer_pos[D2_KV_MAX_LAYER];
    uint64_t appends, reads, resets;
    const char *fail;
} D2KvGuard;
void d2_kv_init(D2KvGuard *k, uint64_t epoch, uint32_t layers, uint32_t max_pos);
int d2_kv_append(D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t gen);
int d2_kv_read(D2KvGuard *k, uint32_t layer, uint32_t pos, uint64_t gen);
int d2_kv_advance(D2KvGuard *k, uint32_t next_pos);
int d2_kv_reset(D2KvGuard *k, uint64_t new_gen); /* sequence boundary only */
#endif
