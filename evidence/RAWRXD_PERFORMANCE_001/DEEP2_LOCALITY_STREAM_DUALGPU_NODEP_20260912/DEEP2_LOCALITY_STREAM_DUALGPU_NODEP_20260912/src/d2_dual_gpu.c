#include "d2_dual_gpu.h"

int d2_dual_gpu_choose(const D2Residency *r, const D2Locality *l, uint32_t expert,
                       uint64_t tid, uint64_t bytes, const D2PlacementCost *c, uint32_t *out) {
    uint32_t d, best = 0;
    uint64_t bestv = UINT64_MAX;
    int found = 0;
    if (!r || !l || !c || !out || expert >= D2_MAX_EXPERTS || !bytes) return D2_EINVAL;
    for (d = 0; d < D2_MAX_DEVICES; ++d) {
        const D2DeviceResidency *v = &r->dev[d];
        size_t idx;
        uint64_t score, need, freeb, pressure;
        if (!v->healthy) continue;
        freeb = v->budget_bytes >= v->used_bytes ? v->budget_bytes - v->used_bytes : 0;
        need = d2_residency_find(r, d, tid, &idx) == D2_OK ? 0 : bytes;
        if (need > v->budget_bytes) continue;
        pressure = freeb >= need ? 0 : (need - freeb);
        score = c->exec_ns[d] + (need ? c->load_ns[d] : 0) + (pressure >> 10);
        if (l->expert[expert].resident_mask & (1u << d)) {
            score = score > c->cross_copy_ns ? score - c->cross_copy_ns : 0;
        }
        if (score < bestv) {
            bestv = score;
            best = d;
            found = 1;
        }
    }
    if (!found) return D2_ENOSPC;
    *out = best;
    return D2_OK;
}
