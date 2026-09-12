/* ur_slot.c — cache slots + runtime lifetime */
#include "ur_internal.h"
#include <stdlib.h>
#include <string.h>

UrCacheSlot *ur_cache_find(UrRuntime *r, UrRegionId id)
{
    uint32_t i;
    for (i = 0; i < UR_CACHE_CAP; i++)
        if (r->cache[i].used && r->cache[i].id == id) return &r->cache[i];
    return 0;
}

UrCacheSlot *ur_cache_alloc(UrRuntime *r, UrRegionId id)
{
    uint32_t i;
    for (i = 0; i < UR_CACHE_CAP; i++) if (!r->cache[i].used) {
        memset(&r->cache[i], 0, sizeof r->cache[i]);
        r->cache[i].used = 1;
        r->cache[i].id = id;
        r->cache[i].state = UR_COLD;
        return &r->cache[i];
    }
    return 0;
}

void ur_runtime_init(UrRuntime *r, UrProviderVTable prov, UrOwner owner)
{
    if (!r) return;
    memset(r, 0, sizeof *r);
    ur_index_clear(&r->index);
    ur_op_clear(&r->auth);
    r->provider = prov;
    r->owner = owner;
    ur_sync_init(&r->sync);
}

void ur_runtime_set_device(UrRuntime *r, UrDeviceVTable dev)
{
    if (r) r->device = dev;
}

void ur_runtime_set_host_budget(UrRuntime *r, uint64_t bytes)
{
    if (r) r->host_budget = bytes;
}

uint64_t ur_cache_resident_bytes(const UrRuntime *r)
{
    uint32_t i; uint64_t n = 0;
    if (!r) return 0;
    for (i = 0; i < UR_CACHE_CAP; i++)
        if (r->cache[i].used && r->cache[i].bytes) n += r->cache[i].length;
    return n;
}

void ur_runtime_shutdown(UrRuntime *r)
{
    uint32_t i;
    if (!r) return;
    for (i = 0; i < UR_CACHE_CAP; i++) {
        if (!r->cache[i].used) continue;
        ur_slot_drop_device(r, &r->cache[i]);
        if (r->cache[i].bytes) free(r->cache[i].bytes);
    }
    ur_sync_kill(&r->sync);
    memset(r, 0, sizeof *r);
}
