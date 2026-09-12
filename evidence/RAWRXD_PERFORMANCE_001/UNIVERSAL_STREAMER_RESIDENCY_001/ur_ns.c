/* ur_ns.c — model namespace invalidation (no family names) */
#include "ur_internal.h"
#include <stdlib.h>

int ur_invalidate_model(UrRuntime *r, UrModelId model)
{
    uint32_t i;
    if (!r || !model) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    for (i = 0; i < UR_CACHE_CAP; i++) {
        UrCacheSlot *s = &r->cache[i];
        if (!s->used || s->desc.model != model) continue;
        if (s->copy_inflight) {
            r->tel.reject_evict_inflight++;
            ur_sync_unlock(&r->sync);
            return UR_E_BUSY;
        }
        ur_slot_drop_device(r, s);
        if (s->bytes) { free(s->bytes); s->bytes = 0; }
        s->length = 0; s->pin_count = 0; s->mg_claimed = 0;
        s->state = UR_COLD; s->generation++;
        r->tel.reject_stale_model++;
        r->tel.evict_to_cold++;
    }
    ur_sync_unlock(&r->sync);
    return UR_OK;
}
