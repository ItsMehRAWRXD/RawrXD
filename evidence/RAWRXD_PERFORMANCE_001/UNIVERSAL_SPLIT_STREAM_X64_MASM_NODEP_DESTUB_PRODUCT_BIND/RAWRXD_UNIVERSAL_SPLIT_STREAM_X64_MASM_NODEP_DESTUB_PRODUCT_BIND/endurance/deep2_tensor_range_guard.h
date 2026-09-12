/* deep2_tensor_range_guard.h */
#ifndef DEEP2_TENSOR_RANGE_GUARD_H
#define DEEP2_TENSOR_RANGE_GUARD_H
#include <stdint.h>
typedef struct {
    uint32_t shard; uint64_t off, bytes; uint32_t codec;
    uint64_t d0, d1;
} D2Range;
typedef struct {
    uint64_t ok, bad;
    const char *fail;
} D2RangeGuard;
void d2_rg_init(D2RangeGuard *g);
int d2_rg_check(D2RangeGuard *g, const D2Range *auth, uint64_t off, uint64_t n);
#endif
