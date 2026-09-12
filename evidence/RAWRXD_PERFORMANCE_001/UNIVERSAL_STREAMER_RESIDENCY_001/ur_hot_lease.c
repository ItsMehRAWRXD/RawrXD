/* ur_hot_lease.c — HOT identity / validity / reset */
#include "ur_internal.h"

int ur_hot_identity(UrRuntime *r, UrRegionId id, UrHotIdentity *out)
{
    UrCacheSlot *s;
    if (!r || !id || !out) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s || s->state != UR_HOT) { ur_sync_unlock(&r->sync); return UR_E_STATE; }
    out->model = s->desc.model; out->model_gen = s->desc.model_gen;
    out->region = s->id; out->residency_gen = s->generation;
    out->device = s->device_id; out->alloc_gen = s->dev_alloc_gen;
    out->source_gen = s->hot_source_gen; out->bytes = s->length;
    out->handle = s->dev_handle;
    ur_sync_unlock(&r->sync);
    return UR_OK;
}

int ur_hot_valid(UrRuntime *r, UrRegionId id, UrAllocGeneration agen)
{
    UrCacheSlot *s; int ok;
    if (!r || !id || !agen) return 0;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    ok = s && s->state == UR_HOT && s->dev_alloc_gen == agen && s->dev_handle;
    ur_sync_unlock(&r->sync);
    return ok;
}

int ur_hot_reset(UrRuntime *r, UrRegionId id)
{
    UrCacheSlot *s;
    if (!r || !id) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s) { ur_sync_unlock(&r->sync); return UR_E_BOUND; }
    ur_slot_drop_device(r, s);
    if (s->state == UR_HOT) s->state = UR_WARM;
    ur_sync_unlock(&r->sync);
    return UR_OK;
}
