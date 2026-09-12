/* ur_promote.c — residency commits HOT after backend copy completes */
#include "ur_internal.h"

int ur_region_state(UrRuntime *r, UrRegionId id, UrResidencyState *out)
{
    UrCacheSlot *s;
    if (!r || !id || !out) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s) { ur_sync_unlock(&r->sync); return UR_E_BOUND; }
    *out = s->state;
    ur_sync_unlock(&r->sync);
    return UR_OK;
}

int ur_copy_inflight(UrRuntime *r, UrRegionId id)
{
    UrCacheSlot *s; int v;
    if (!r || !id) return 0;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    v = s && s->copy_inflight;
    ur_sync_unlock(&r->sync);
    return v;
}

int ur_promote_hot_at(UrRuntime *r, UrRegionId id, UrGeneration expect)
{
    UrCacheSlot *s; const uint8_t *src; uint64_t n; UrGeneration gen;
    UrDeviceId did = 0; UrAllocGeneration ag = 0; void *h = 0; int rc, gpu;
    if (!r || !id) return UR_E_ARG;
    ur_sync_lock(&r->sync);
    s = ur_cache_find(r, id);
    if (!s || !s->bytes) { ur_sync_unlock(&r->sync); return UR_E_STATE; }
    if (s->state == UR_HOT || s->copy_inflight) {
        r->tel.reject_dup_upload++; ur_sync_unlock(&r->sync); return UR_E_DUP;
    }
    if (s->state != UR_WARM) { ur_sync_unlock(&r->sync); return UR_E_STATE; }
    if (expect && expect != s->generation) {
        r->tel.reject_stale_gpu++; ur_sync_unlock(&r->sync); return UR_E_AUTH;
    }
    if (!r->device.alloc_copy && !r->device.upload_begin) {
        s->state = UR_HOT; ur_sync_unlock(&r->sync); return UR_OK;
    }
    gpu = r->device.kind == UR_DEVKIND_GPU;
    s->copy_inflight = 1; s->pin_count++;
    src = s->bytes; n = s->length; gen = s->generation;
    if (gpu) r->tel.gpu_copy_issued++;
    ur_sync_unlock(&r->sync);
    if (r->device.upload_begin && r->device.upload_wait) {
        rc = r->device.upload_begin(r->device.ctx, src, n, &did, &ag, &h);
        if (!rc) rc = r->device.upload_wait(r->device.ctx, h, src, n);
    } else {
        rc = r->device.alloc_copy(r->device.ctx, src, n, &did, &ag, &h);
    }
    ur_sync_lock(&r->sync);
    s->copy_inflight = 0;
    if (rc) { s->pin_count--; ur_sync_unlock(&r->sync); return rc; }
    if (s->generation != gen || s->state != UR_WARM) {
        if (r->device.release) r->device.release(r->device.ctx, h);
        r->tel.reject_stale_gpu++; s->pin_count--;
        ur_sync_unlock(&r->sync); return UR_E_AUTH;
    }
    s->dev_handle = h; s->device_id = did;
    s->dev_alloc_gen = ag; s->hot_source_gen = gen;
    s->state = UR_HOT; s->pin_count--;
    r->tel.device_copy_bytes += n; r->tel.device_uploads++;
    if (gpu) { r->tel.gpu_allocs++; r->tel.gpu_copy_completed++; r->tel.gpu_copy_bytes += n; }
    ur_sync_unlock(&r->sync);
    return UR_OK;
}

int ur_promote_hot(UrRuntime *r, UrRegionId id)
{ return ur_promote_hot_at(r, id, 0); }
