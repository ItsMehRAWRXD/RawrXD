/* ur_index.c */
#include "ur_index.h"
#include <string.h>

void ur_index_clear(UrShardIndex *ix)
{
    if (!ix) return;
    memset(ix, 0, sizeof *ix);
}

UrRegionId ur_region_id_from_desc(const UrRegionDesc *d)
{
    /* FNV-1a 64 over packed fields */
    const uint8_t *p;
    uint64_t h = 14695981039346656037ull;
    uint8_t buf[40];
    size_t i;
    if (!d) return 0;
    memcpy(buf + 0, &d->model, 8);
    memcpy(buf + 8, &d->model_gen, 8);
    memcpy(buf + 16, &d->provider, 4);
    memcpy(buf + 20, &d->shard, 4);
    memcpy(buf + 24, &d->offset, 8);
    memcpy(buf + 32, &d->length, 8);
    p = buf;
    for (i = 0; i < 40; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h ? h : 1;
}

int ur_index_put(UrShardIndex *ix, UrRegionId id, const UrRegionDesc *d)
{
    uint32_t i;
    if (!ix || !d || !id || !d->length) return UR_E_ARG;
    for (i = 0; i < UR_INDEX_CAP; i++) {
        if (ix->slots[i].used && ix->slots[i].id == id) {
            if (memcmp(&ix->slots[i].desc, d, sizeof *d) != 0) return UR_E_DUP;
            return UR_OK;
        }
    }
    for (i = 0; i < UR_INDEX_CAP; i++) {
        if (!ix->slots[i].used) {
            ix->slots[i].used = 1;
            ix->slots[i].id = id;
            ix->slots[i].desc = *d;
            ix->count++;
            return UR_OK;
        }
    }
    return UR_E_OOM;
}

int ur_index_get(const UrShardIndex *ix, UrRegionId id, UrRegionDesc *out)
{
    uint32_t i;
    if (!ix || !out || !id) return UR_E_ARG;
    for (i = 0; i < UR_INDEX_CAP; i++) {
        if (ix->slots[i].used && ix->slots[i].id == id) {
            *out = ix->slots[i].desc;
            return UR_OK;
        }
    }
    return UR_E_BOUND;
}
