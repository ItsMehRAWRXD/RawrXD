/* ur_demote.c — release / HOT→WARM / evict→COLD */
#include "ur_internal.h"
#include <stdlib.h>

int ur_release_region(UrRuntime *r, UrRegionId id)
{
    UrCacheSlot *s; int rc;
    if (!r || !id) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (s && s->pin_count) { s->pin_count--; ur_sync_unlock(&r->sync); return UR_OK; }
    rc = ur_lease_release(r, id);
    ur_sync_unlock(&r->sync);
    return rc;
}

int ur_demote_to_warm(UrRuntime *r, UrRegionId id)
{
    UrCacheSlot *s;
    if (!r || !id) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s || s->state != UR_HOT) { ur_sync_unlock(&r->sync); return UR_E_STATE; }
    ur_slot_drop_device(r, s);
    s->state = UR_WARM;
    r->tel.demote_hot_warm++;
    ur_sync_unlock(&r->sync);
    return UR_OK;
}

int ur_evict_region(UrRuntime *r, UrRegionId id)
{
    UrCacheSlot *s;
    if (!r || !id) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s) { ur_sync_unlock(&r->sync); return UR_E_BOUND; }
    if (s->copy_inflight) {
        r->tel.reject_evict_inflight++;
        ur_sync_unlock(&r->sync);
        return UR_E_BUSY;
    }
    if (s->pin_count) { ur_sync_unlock(&r->sync); return UR_E_PIN; }
    if (s->state == UR_MG_IN_PROGRESS) { ur_sync_unlock(&r->sync); return UR_E_STATE; }
    ur_slot_drop_device(r, s);
    if (s->bytes) { free(s->bytes); s->bytes = 0; }
    s->length = 0; s->state = UR_COLD; s->mg_claimed = 0;
    s->generation++;
    r->tel.evict_to_cold++;
    ur_sync_unlock(&r->sync);
    return UR_OK;
}
