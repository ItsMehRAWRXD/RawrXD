#include "d2_residency_finishers.h"
#include <limits.h>

void d2r_init(D2ResidencyRegion* r, uint64_t region_id, uint64_t generation,
              uint64_t offset, uint64_t length, uint32_t codec, uint32_t owner_id) {
    if (!r) return;
    r->region_id = region_id; r->generation = generation;
    r->offset = offset; r->length = length; r->resident_bytes = 0;
    r->codec = codec; r->owner_id = owner_id; r->pin_count = 0;
    r->state = D2R_COLD; r->load_inflight = 0;
}

int d2r_begin_first_touch(D2ResidencyRegion* r, D2ResidencyCounters* c,
                          uint64_t generation, uint32_t owner_id) {
    if (!r || !c || generation != r->generation || owner_id != r->owner_id) return 0;
    if (r->state != D2R_COLD || r->load_inflight) return 0;
    r->state = D2R_LOADING; r->load_inflight = 1; c->first_touch_wins++;
    return 1;
}

int d2r_join_first_touch(const D2ResidencyRegion* r, D2ResidencyCounters* c,
                         uint64_t generation) {
    if (!r || !c || generation != r->generation) return 0;
    if (r->state != D2R_LOADING || !r->load_inflight) return 0;
    c->joined_loads++; return 1;
}

int d2r_finish_first_touch(D2ResidencyRegion* r, D2ResidencyCounters* c,
                           int success, uint64_t resident_bytes) {
    if (!r || !c || r->state != D2R_LOADING || !r->load_inflight) return 0;
    r->load_inflight = 0;
    if (!success || resident_bytes == 0 || resident_bytes > r->length) {
        r->state = D2R_COLD; r->resident_bytes = 0; c->failed_loads++; return 0;
    }
    r->resident_bytes = resident_bytes; r->state = D2R_WARM; return 1;
}

int d2r_contains(const D2ResidencyRegion* r, uint64_t generation,
                 uint64_t req_offset, uint64_t req_length, uint32_t codec) {
    uint64_t end, rend;
    if (!r || generation != r->generation || codec != r->codec) return 0;
    if (r->state < D2R_WARM || !req_length) return 0;
    if (req_offset > UINT64_MAX - req_length) return 0;
    if (r->offset > UINT64_MAX - r->resident_bytes) return 0;
    end = req_offset + req_length; rend = r->offset + r->resident_bytes;
    return req_offset >= r->offset && end <= rend;
}

int d2r_pin(D2ResidencyRegion* r) {
    if (!r || r->state < D2R_WARM || r->pin_count == UINT32_MAX) return 0;
    r->pin_count++; if (r->state == D2R_WARM) r->state = D2R_HOT; return 1;
}
int d2r_unpin(D2ResidencyRegion* r) {
    if (!r || !r->pin_count) return 0;
    r->pin_count--;
    return 1;
}
int d2r_demote_hot_to_warm(D2ResidencyRegion* r, D2ResidencyCounters* c) {
    if (!r || !c || r->state != D2R_HOT || r->pin_count) return 0;
    r->state = D2R_WARM; c->hot_to_warm++; return 1;
}
int d2r_demote_warm_to_cold(D2ResidencyRegion* r, D2ResidencyCounters* c) {
    if (!r || !c || r->state != D2R_WARM || r->pin_count) return 0;
    r->state = D2R_COLD; r->resident_bytes = 0; c->warm_to_cold++; return 1;
}

int d2r_parent_proof_pass(const D2ResidencyParentProof* p) {
    return p && p->bind16_authority && p->bind16_pass_tokens >= 16 &&
           p->persistent_decode && p->gpu_resident_decode && p->dual_gpu_used &&
           p->resident_bytes > 0 && p->weight_upload_delta == 0 &&
           p->reload_delta == 0 && p->device_create_delta == 0 &&
           p->model_load_delta == 0 && p->pin_evict_delta == 0;
}

uint32_t d2r_top15_pass_mask(const D2ResidencyParentProof* p,
                             int single_owner, int generation_ok,
                             int first_touch_ok, int join_ok, int rollback_ok,
                             int range_ok, int codec_ok, int pin_ok,
                             int demotion_ok) {
    uint32_t m = 0;
    if (single_owner) m |= 1u<<0;
    if (generation_ok) m |= 1u<<1;
    if (first_touch_ok) m |= 1u<<2;
    if (join_ok) m |= 1u<<3;
    if (rollback_ok) m |= 1u<<4;
    if (range_ok) m |= 1u<<5;
    if (codec_ok) m |= 1u<<6;
    if (pin_ok) m |= 1u<<7;
    if (demotion_ok) m |= 1u<<8;
    if (p && p->weight_upload_delta == 0) m |= 1u<<9;
    if (p && p->reload_delta == 0) m |= 1u<<10;
    if (p && p->device_create_delta == 0 && p->model_load_delta == 0) m |= 1u<<11;
    if (p && p->resident_bytes > 0) m |= 1u<<12;
    if (d2r_parent_proof_pass(p)) m |= 1u<<13;
    m |= 1u<<14; /* authority/promotion are intentionally not minted by this side drop */
    return m;
}
