#include "deep2_nodep_missing15.h"

static d2_u64 d2_abs_delta(d2_u64 a, d2_u64 b) { return (a >= b) ? (a - b) : (b - a); }

d2_i32 d2_post_forward_survival(const D2SurvivalOps *ops, D2SurvivalResult *out) {
    if (!ops || !out || !ops->wait_queue_idle || !ops->submit_noop || !ops->submit_embd)
        return D2_E_BAD_ARG;

    out->promote = 0;
    out->post_forward_device_alive = 0;
    out->post_forward_noop_pass = 0;
    out->post_forward_embd_pass = 0;

    out->wait_rc = ops->wait_queue_idle(ops->ctx);
    if (out->wait_rc != 0) return D2_E_DEVICE_LOST;

    out->noop_rc = ops->submit_noop(ops->ctx);
    if (out->noop_rc != 0) return D2_E_DEVICE_LOST;
    out->post_forward_noop_pass = 1;

    out->embd_rc = ops->submit_embd(ops->ctx);
    if (out->embd_rc != 0) return D2_E_DEVICE_LOST;

    out->post_forward_embd_pass = 1;
    out->post_forward_device_alive = 1;
    return D2_OK;
}

d2_i32 d2_resource_snapshot_validate(const D2ResourceSnapshot *s) {
    d2_u64 used;
    if (!s) return D2_E_BAD_ARG;
    if (s->stage >= D2_STAGE_COUNT) return D2_E_BAD_ARG;
    if (s->device_lost) return D2_E_DEVICE_LOST;

    used = s->weight_resident_bytes;
    if (~used < s->kv_resident_bytes) return D2_E_BUDGET;
    used += s->kv_resident_bytes;
    if (~used < s->persistent_bytes) return D2_E_BUDGET;
    used += s->persistent_bytes;
    if (~used < s->scratch_current_bytes) return D2_E_BUDGET;
    used += s->scratch_current_bytes;
    if (~used < s->transient_current_bytes) return D2_E_BUDGET;
    used += s->transient_current_bytes;
    if (used > s->gpu_total_budget) return D2_E_BUDGET;
    if (s->scratch_current_bytes > s->scratch_peak_bytes) return D2_E_BAD_ARG;
    if (s->transient_current_bytes > s->transient_peak_bytes) return D2_E_BAD_ARG;
    return D2_OK;
}

d2_i32 d2_plateau_init(D2PlateauState *st, const D2ResourceSnapshot *base,
                       d2_u64 transient_delta, d2_u64 alloc_delta, d2_u64 cmd_delta) {
    if (!st || !base) return D2_E_BAD_ARG;
    st->base = *base;
    st->last = *base;
    st->max_transient_delta = 0;
    st->max_alloc_count_delta = 0;
    st->max_cmd_count_delta = 0;
    st->allowed_transient_delta = transient_delta;
    st->allowed_alloc_count_delta = alloc_delta;
    st->allowed_cmd_count_delta = cmd_delta;
    st->samples = 1;
    st->failed = 0;
    return d2_resource_snapshot_validate(base);
}

d2_i32 d2_plateau_update(D2PlateauState *st, const D2ResourceSnapshot *s) {
    d2_u64 td, ad, cd;
    d2_i32 rc;
    if (!st || !s) return D2_E_BAD_ARG;
    rc = d2_resource_snapshot_validate(s);
    if (rc != D2_OK) { st->failed = 1; return rc; }

    td = d2_abs_delta(s->transient_current_bytes, st->base.transient_current_bytes);
    ad = d2_abs_delta(s->allocation_count, st->base.allocation_count);
    cd = d2_abs_delta(s->command_buffer_count, st->base.command_buffer_count);
    if (td > st->max_transient_delta) st->max_transient_delta = td;
    if (ad > st->max_alloc_count_delta) st->max_alloc_count_delta = ad;
    if (cd > st->max_cmd_count_delta) st->max_cmd_count_delta = cd;

    if (td > st->allowed_transient_delta ||
        ad > st->allowed_alloc_count_delta ||
        cd > st->allowed_cmd_count_delta) {
        st->failed = 1;
        st->last = *s;
        st->samples++;
        return D2_E_RESOURCE_GROWTH;
    }

    st->last = *s;
    st->samples++;
    return D2_OK;
}

d2_i32 d2_plateau_pass(const D2PlateauState *st) {
    if (!st) return D2_E_BAD_ARG;
    return st->failed ? D2_E_RESOURCE_GROWTH : D2_OK;
}

d2_i32 d2_arena_plan_finalize(D2ArenaPlan *p) {
    d2_u64 total = 0, v[9];
    d2_u32 i;
    if (!p) return D2_E_BAD_ARG;
    v[0]=p->driver_reserve; v[1]=p->weights; v[2]=p->kv; v[3]=p->persistent;
    v[4]=p->scratch; v[5]=p->activation_a; v[6]=p->activation_b;
    v[7]=p->command_descriptor_reserve; v[8]=0;
    for (i=0; i<8; ++i) {
        if (~total < v[i]) { p->full_gpu_resident = 0; return D2_E_BUDGET; }
        total += v[i];
    }
    p->total_required = total;
    p->full_gpu_resident = (total <= p->gpu_budget) ? 1u : 0u;
    return p->full_gpu_resident ? D2_OK : D2_E_BUDGET;
}

d2_i32 d2_pingpong_validate(d2_u64 a_base, d2_u64 a_size, d2_u64 b_base, d2_u64 b_size) {
    d2_u64 a_end, b_end;
    if (!a_size || !b_size) return D2_E_BAD_ARG;
    if (~a_base < a_size || ~b_base < b_size) return D2_E_RANGE;
    a_end = a_base + a_size; b_end = b_base + b_size;
    if (a_base < b_end && b_base < a_end) return D2_E_RANGE;
    return D2_OK;
}

d2_i32 d2_descriptor_bound_check(d2_u64 used, d2_u64 capacity) {
    if (!capacity) return D2_E_BAD_ARG;
    return used <= capacity ? D2_OK : D2_E_RESOURCE_GROWTH;
}

d2_i32 d2_command_ring_validate(d2_u64 in_flight, d2_u64 ring_capacity) {
    if (!ring_capacity) return D2_E_BAD_ARG;
    return in_flight <= ring_capacity ? D2_OK : D2_E_SYNC;
}

d2_u32 d2_submission_chunk_count(d2_u32 blocks, d2_u32 max_blocks_per_submit) {
    if (!blocks || !max_blocks_per_submit) return 0;
    return (blocks + max_blocks_per_submit - 1u) / max_blocks_per_submit;
}

d2_i32 d2_sync_validate(const D2SyncState *s) {
    if (!s) return D2_E_BAD_ARG;
    if (s->completed_serial > s->submit_serial) return D2_E_SYNC;
    if (s->fence_serial > s->submit_serial) return D2_E_SYNC;
    if (s->semaphore_wait_serial > s->submit_serial) return D2_E_SYNC;
    if (s->resource_retire_serial < s->resource_last_use_serial) return D2_E_SYNC;
    if (s->resource_retire_serial > s->completed_serial) return D2_E_SYNC;
    return D2_OK;
}

d2_i32 d2_range_validate(const D2Range *r) {
    d2_u64 end;
    if (!r || !r->size) return D2_E_BAD_ARG;
    if (r->offset > r->size) return D2_E_RANGE;
    if (~r->offset < r->length) return D2_E_RANGE;
    end = r->offset + r->length;
    if (end > r->size) return D2_E_RANGE;
    if (~r->base < end) return D2_E_RANGE;
    return D2_OK;
}

d2_i32 d2_barrier_validate(d2_u64 producer_serial, d2_u64 barrier_serial, d2_u64 consumer_serial) {
    if (producer_serial > barrier_serial) return D2_E_SYNC;
    if (barrier_serial > consumer_serial) return D2_E_SYNC;
    return D2_OK;
}

d2_i32 d2_queue_ownership_validate(d2_u32 src_family, d2_u32 dst_family,
                                   d2_u32 current_owner, d2_u32 concurrent_sharing) {
    if (concurrent_sharing) return D2_OK;
    if (current_owner != src_family) return D2_E_SYNC;
    if (src_family == dst_family) return D2_OK;
    return D2_OK; /* Host must perform the actual release/acquire; this validates declared ownership input. */
}

d2_i32 d2_u64_add_checked(d2_u64 a, d2_u64 b, d2_u64 *out) {
    if (!out) return D2_E_BAD_ARG;
    if (~a < b) return D2_E_RANGE;
    *out = a + b;
    return D2_OK;
}

d2_i32 d2_bisect_init(D2BisectState *b, d2_u32 known_pass, d2_u32 known_fail) {
    if (!b || known_pass >= known_fail) return D2_E_BAD_ARG;
    b->low_pass = known_pass;
    b->high_fail = known_fail;
    b->done = 0;
    b->next_probe = known_pass + ((known_fail - known_pass) >> 1);
    if (b->next_probe == known_pass) b->next_probe++;
    return D2_OK;
}

d2_i32 d2_bisect_record(D2BisectState *b, d2_u32 probe, d2_u32 survived) {
    if (!b || b->done || probe <= b->low_pass || probe >= b->high_fail) return D2_E_BAD_ARG;
    if (survived) b->low_pass = probe; else b->high_fail = probe;
    if (b->high_fail - b->low_pass <= 1u) {
        b->done = 1;
        b->next_probe = b->high_fail;
        return D2_OK;
    }
    b->next_probe = b->low_pass + ((b->high_fail - b->low_pass) >> 1);
    return D2_OK;
}

d2_i32 d2_target2_authority_check(const D2Token2Witness *w) {
    if (!w) return D2_E_BAD_ARG;
    if (w->target_tokens != 2) return D2_E_AUTHORITY;
    if (w->forward_calls < 2 || w->full_block_forward_calls < 2) return D2_E_AUTHORITY;
    if (w->sealed_logits_reuse_token1 != 0) return D2_E_AUTHORITY;
    if (w->embd_calls_after_advance < 1) return D2_E_AUTHORITY;
    if (w->position0 != 0 || w->position1 != 1) return D2_E_AUTHORITY;
    if (w->commit_calls != 2 || w->advance_calls != 2 || w->generated != 2) return D2_E_AUTHORITY;
    if (w->device_lost != 0) return D2_E_DEVICE_LOST;
    if (!w->auth_autoregressive_commit_granted) return D2_E_AUTHORITY;
    if (w->full_model_tps_authority != 0 || w->promote != 0) return D2_E_AUTHORITY;
    return D2_OK;
}
