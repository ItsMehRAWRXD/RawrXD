#include "d2_residency.h"
#include <string.h>

void d2_residency_init(D2Residency *r, uint64_t b0, uint64_t b1, uint64_t bw0, uint64_t bw1) {
    if (!r) return;
    memset(r, 0, sizeof(*r));
    r->dev[0].budget_bytes = b0;
    r->dev[1].budget_bytes = b1;
    r->dev[0].bandwidth_bytes_s = bw0;
    r->dev[1].bandwidth_bytes_s = bw1;
    r->dev[0].healthy = 1;
    r->dev[1].healthy = 1;
}

int d2_residency_find(const D2Residency *r, uint32_t d, uint64_t id, size_t *idx) {
    size_t i;
    if (!r || d >= D2_MAX_DEVICES) return D2_EINVAL;
    for (i = 0; i < r->dev[d].count; ++i) {
        if (r->dev[d].item[i].tensor_id == id && r->dev[d].item[i].state == D2_RES_HOT) {
            if (idx) *idx = i;
            return D2_OK;
        }
    }
    return D2_ENOTFOUND;
}

int d2_residency_evict_one(D2Residency *r, D2Locality *l, uint32_t d, uint64_t token) {
    size_t i, best = (size_t)-1;
    uint64_t best_score = UINT64_MAX;
    D2DeviceResidency *v;
    if (!r || !l || d >= D2_MAX_DEVICES) return D2_EINVAL;
    v = &r->dev[d];
    for (i = 0; i < v->count; ++i) {
        D2Resident *x = &v->item[i];
        uint64_t s;
        if (x->pin_count || x->state != D2_RES_HOT) continue;
        s = d2_locality_score(l, x->expert_id, d, x->bytes);
        if (x->last_use_token == token) s += 8000000000ULL;
        if (s < best_score) {
            best_score = s;
            best = i;
        }
    }
    if (best == (size_t)-1) return D2_ENOSPC;
    {
        D2Resident victim = v->item[best];
        if (v->used_bytes < victim.bytes) return D2_ESTATE;
        v->used_bytes -= victim.bytes;
        d2_locality_mark_resident(l, victim.expert_id, d, 0, 0);
        r->counters.evictions[d]++;
        v->item[best] = v->item[v->count - 1];
        v->count--;
    }
    return D2_OK;
}

int d2_residency_reserve(D2Residency *r, D2Locality *l, uint32_t d, uint64_t id,
                         uint32_t expert, uint64_t bytes, uint64_t token, size_t *slot) {
    D2DeviceResidency *v;
    size_t existing;
    if (!r || !l || d >= D2_MAX_DEVICES || !id || !bytes || expert >= D2_MAX_EXPERTS) return D2_EINVAL;
    v = &r->dev[d];
    if (!v->healthy) return D2_ESTATE;
    if (d2_residency_find(r, d, id, &existing) == D2_OK) {
        v->item[existing].last_use_token = token;
        r->counters.locality_hits[d]++;
        if (slot) *slot = existing;
        return D2_OK;
    }
    r->counters.locality_misses[d]++;
    if (bytes > v->budget_bytes) return D2_ENOSPC;
    while (v->used_bytes + bytes > v->budget_bytes) {
        int rc = d2_residency_evict_one(r, l, d, token);
        if (rc) return rc;
    }
    if (v->count >= D2_MAX_RESIDENT) return D2_ENOSPC;
    {
        size_t i = v->count++;
        memset(&v->item[i], 0, sizeof(v->item[i]));
        v->item[i].tensor_id = id;
        v->item[i].expert_id = expert;
        v->item[i].bytes = bytes;
        v->item[i].device = d;
        v->item[i].state = D2_RES_LOADING;
        v->item[i].last_use_token = token;
        v->used_bytes += bytes;
        if (slot) *slot = i;
    }
    return D2_OK;
}

int d2_residency_commit(D2Residency *r, D2Locality *l, uint32_t d, size_t slot) {
    D2DeviceResidency *v;
    if (!r || !l || d >= D2_MAX_DEVICES) return D2_EINVAL;
    v = &r->dev[d];
    if (slot >= v->count || v->item[slot].state != D2_RES_LOADING) return D2_ESTATE;
    v->item[slot].state = D2_RES_HOT;
    d2_locality_mark_resident(l, v->item[slot].expert_id, d, v->item[slot].bytes, 1);
    r->counters.device_load_ok[d]++;
    return D2_OK;
}

int d2_residency_pin(D2Residency *r, uint32_t d, uint64_t id, int delta, uint64_t token) {
    size_t i;
    D2DeviceResidency *v;
    if (!r || d >= D2_MAX_DEVICES) return D2_EINVAL;
    v = &r->dev[d];
    if (d2_residency_find(r, d, id, &i)) return D2_ENOTFOUND;
    if (delta > 0) {
        v->item[i].pin_count += (uint32_t)delta;
    } else {
        uint32_t x = (uint32_t)(-delta);
        if (v->item[i].pin_count < x) return D2_ESTATE;
        v->item[i].pin_count -= x;
    }
    v->item[i].last_use_token = token;
    return D2_OK;
}
