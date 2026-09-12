/* deep2_longrun_stats.h — constant-memory rolling stats */
#ifndef DEEP2_LONGRUN_STATS_H
#define DEEP2_LONGRUN_STATS_H
#include <stdint.h>
typedef struct {
    uint64_t n, min_v, max_v, sum;
    uint64_t bucket[8];
} D2Stat;
void d2_st_init(D2Stat *s);
void d2_st_add(D2Stat *s, uint64_t v);
#endif
