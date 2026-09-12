/* ss_plan_load_slice.c — load contiguous byte range from plan shard */
#include "ss_model_plan.h"
#include <stdio.h>
#include <stdlib.h>
int ss_plan_load_slice(const SsModelPlan *plan, uint32_t shard, uint64_t off,
                       uint64_t n, void **out)
{
    FILE *f; void *buf; size_t got;
    if (!plan || !out || !n || shard >= plan->shardCount) return 1;
    if (!plan->shardPaths[shard][0]) return 1;
    *out = 0;
    f = fopen(plan->shardPaths[shard], "rb");
    if (!f) return 1;
    if (_fseeki64(f, (__int64)off, SEEK_SET)) { fclose(f); return 1; }
    buf = malloc((size_t)n);
    if (!buf) { fclose(f); return 1; }
    got = fread(buf, 1, (size_t)n, f); fclose(f);
    if (got != (size_t)n) { free(buf); return 1; }
    *out = buf;
    return 0;
}
