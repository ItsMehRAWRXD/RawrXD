/* ss_plan_load.c — exact range read from plan-derived shard/offset */
#include "ss_plan_load.h"
#include <stdio.h>
#include <stdlib.h>
int ss_plan_load_ref(const SsModelPlan *plan, const SsTensorRef *ref, void **out, uint64_t *n)
{
    FILE *f; void *buf; size_t got;
    if (!plan || !ref || !ref->present || !out || !n) return 1;
    if (ref->shardIndex >= plan->shardCount || !ref->bytes) return 1;
    if (!plan->shardPaths[ref->shardIndex][0]) return 1;
    *out = 0; *n = 0;
    f = fopen(plan->shardPaths[ref->shardIndex], "rb");
    if (!f) return 1;
    if (_fseeki64(f, (__int64)ref->fileOffset, SEEK_SET)) { fclose(f); return 1; }
    buf = malloc((size_t)ref->bytes);
    if (!buf) { fclose(f); return 1; }
    got = fread(buf, 1, (size_t)ref->bytes, f); fclose(f);
    if (got != (size_t)ref->bytes) { free(buf); return 1; }
    *out = buf; *n = ref->bytes;
    return 0;
}
