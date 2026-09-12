/* ur_internal.h — cache / alias / device slot helpers */
#ifndef UR_INTERNAL_H
#define UR_INTERNAL_H
#include "ur_residency.h"

UrCacheSlot *ur_cache_find(UrRuntime *r, UrRegionId id);
UrCacheSlot *ur_cache_alloc(UrRuntime *r, UrRegionId id);
void ur_slot_drop_device(UrRuntime *r, UrCacheSlot *s);

int ur_range_contains(const UrRegionDesc *host, const UrRegionDesc *want);
int ur_range_overlaps(const UrRegionDesc *a, const UrRegionDesc *b);
int ur_alias_lookup(UrRuntime *r, const UrRegionDesc *want,
                    UrCacheSlot **host, uint64_t *byte_off);
int ur_lease_add(UrRuntime *r, UrRegionId req, UrRegionId host);
int ur_lease_release(UrRuntime *r, UrRegionId req);
uint64_t ur_cache_resident_bytes(const UrRuntime *r);

#endif
