/* ur_index.h — GENERIC_SHARD_INDEX / region identity table */
#ifndef UR_INDEX_H
#define UR_INDEX_H
#include "ur_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define UR_INDEX_CAP 256

typedef struct {
    UrRegionId id;
    UrRegionDesc desc;
    uint8_t used;
} UrIndexSlot;

typedef struct {
    UrIndexSlot slots[UR_INDEX_CAP];
    uint32_t count;
} UrShardIndex;

void ur_index_clear(UrShardIndex *ix);
int ur_index_put(UrShardIndex *ix, UrRegionId id, const UrRegionDesc *d);
int ur_index_get(const UrShardIndex *ix, UrRegionId id, UrRegionDesc *out);
/* Stable identity: hash(provider,shard,offset,length) — no name dependence */
UrRegionId ur_region_id_from_desc(const UrRegionDesc *d);

#ifdef __cplusplus
}
#endif
#endif
