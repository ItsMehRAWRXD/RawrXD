/* ur_alias.c — parent/child containment; partial overlap is not a hit */
#include "ur_internal.h"

int ur_range_contains(const UrRegionDesc *h, const UrRegionDesc *w)
{
    uint64_t he, we;
    if (!h || !w || h->model != w->model || h->model_gen != w->model_gen)
        return 0;
    if (h->provider != w->provider || h->shard != w->shard)
        return 0;
    if (w->offset < h->offset) return 0;
    he = h->offset + h->length;
    we = w->offset + w->length;
    if (he < h->offset || we < w->offset) return 0;
    return we <= he;
}

int ur_range_overlaps(const UrRegionDesc *a, const UrRegionDesc *b)
{
    uint64_t ae, be;
    if (!a || !b || a->model != b->model || a->model_gen != b->model_gen)
        return 0;
    if (a->provider != b->provider || a->shard != b->shard)
        return 0;
    ae = a->offset + a->length;
    be = b->offset + b->length;
    if (ae < a->offset || be < b->offset) return 0;
    return a->offset < be && b->offset < ae;
}

int ur_alias_lookup(UrRuntime *r, const UrRegionDesc *want,
                    UrCacheSlot **host, uint64_t *byte_off)
{
    uint32_t i;
    int partial = 0;
    if (!r || !want || !host || !byte_off) return 0;
    for (i = 0; i < UR_CACHE_CAP; i++) {
        UrCacheSlot *s = &r->cache[i];
        if (!s->used || !s->bytes) continue;
        if (s->state != UR_WARM && s->state != UR_HOT) continue;
        if (!ur_range_contains(&s->desc, want)) continue;
        *host = s;
        *byte_off = want->offset - s->desc.offset;
        return 1;
    }
    for (i = 0; i < UR_CACHE_CAP; i++) {
        UrCacheSlot *s = &r->cache[i];
        if (!s->used || !s->bytes) continue;
        if (s->state != UR_WARM && s->state != UR_HOT) continue;
        if (ur_range_overlaps(&s->desc, want)) partial = 1;
    }
    if (partial) r->tel.alias_partial_reject++;
    return 0;
}

int ur_lease_add(UrRuntime *r, UrRegionId req, UrRegionId host)
{
    uint32_t i;
    for (i = 0; i < UR_LEASE_CAP; i++)
        if (r->lease[i].used && r->lease[i].req == req) {
            r->lease[i].pins++;
            return UR_OK;
        }
    for (i = 0; i < UR_LEASE_CAP; i++) if (!r->lease[i].used) {
        r->lease[i].used = 1;
        r->lease[i].req = req;
        r->lease[i].host = host;
        r->lease[i].pins = 1;
        return UR_OK;
    }
    return UR_E_OOM;
}

int ur_lease_release(UrRuntime *r, UrRegionId req)
{
    uint32_t i;
    UrCacheSlot *h;
    for (i = 0; i < UR_LEASE_CAP; i++) {
        if (!r->lease[i].used || r->lease[i].req != req || !r->lease[i].pins)
            continue;
        h = ur_cache_find(r, r->lease[i].host);
        if (!h || !h->pin_count) return UR_E_PIN;
        h->pin_count--;
        r->lease[i].pins--;
        if (!r->lease[i].pins) r->lease[i].used = 0;
        return UR_OK;
    }
    return UR_E_PIN;
}
