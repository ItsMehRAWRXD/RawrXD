#include "ds671_tensor_adapter.h"
#include "ds671_tensor_io.h"
#include <stdint.h>

static int ds671_slots_for_moe(
    const ds671_tensor_adapter *a, uint32_t moe_layer, uint32_t expert_id,
    const ds671_proj_slot **g, const ds671_proj_slot **u,
    const ds671_proj_slot **d) {
    uint32_t blk;
    if (!a || !g || !u || !d) return -1;
    if (expert_id >= a->experts_per_layer) return -1;
    blk = ds671_blk_from_moe(a, moe_layer);
    *g = ds671_find_proj(a, blk, DS671_PROJ_GATE);
    *u = ds671_find_proj(a, blk, DS671_PROJ_UP);
    *d = ds671_find_proj(a, blk, DS671_PROJ_DOWN);
    /* Gate optional (ReLU2); up+down required — match MoEWeightsLoader. */
    if (!*u || !*d) return -1;
    if ((*u)->num_experts && expert_id >= (*u)->num_experts) return -1;
    if ((*d)->num_experts && expert_id >= (*d)->num_experts) return -1;
    if (*g && (*g)->num_experts && expert_id >= (*g)->num_experts) return -1;
    return 0;
}

int ds671_adapter_measure(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t *bytes_out) {
    const ds671_tensor_adapter *a = (const ds671_tensor_adapter *)user;
    const ds671_proj_slot *g = 0, *u = 0, *d = 0;
    uint64_t total;
    (void)expert_id;
    if (!bytes_out) return -1;
    *bytes_out = 0;
    if (ds671_slots_for_moe(a, moe_layer, expert_id, &g, &u, &d)) return -1;
    total = u->bytes_per_expert + d->bytes_per_expert;
    if (g) total += g->bytes_per_expert;
    if (!total) return -1;
    *bytes_out = total;
    return 0;
}

static int ds671_read_slice(
    const ds671_tensor_adapter *a, const ds671_proj_slot *s,
    uint32_t expert_id, uint8_t *dst) {
    const char *path;
    uint64_t off;
    if (!s || !s->bytes_per_expert) return -1;
    if (s->shard_index >= a->shard_count || !a->shard_paths) return -1;
    path = a->shard_paths[s->shard_index];
    if (!path) return -1;
    off = s->file_offset + (uint64_t)expert_id * s->bytes_per_expert;
    return ds671_win_read_at(path, off, dst, s->bytes_per_expert);
}

int ds671_adapter_load(
    void *user, uint32_t moe_layer, uint32_t expert_id,
    uint64_t expected_bytes, uint64_t *handle_out, uint64_t *actual_bytes_out) {
    const ds671_tensor_adapter *a = (const ds671_tensor_adapter *)user;
    const ds671_proj_slot *g = 0, *u = 0, *d = 0;
    uint64_t total = 0, cursor = 0;
    uint8_t *buf;

    if (!handle_out || !actual_bytes_out) return -1;
    *handle_out = 0;
    *actual_bytes_out = 0;
    if (ds671_slots_for_moe(a, moe_layer, expert_id, &g, &u, &d)) return -1;
    total = u->bytes_per_expert + d->bytes_per_expert;
    if (g) total += g->bytes_per_expert;
    if (total != expected_bytes || !total) return -1;

    buf = (uint8_t *)ds671_win_alloc32(total);
    if (!buf) return -1;
    if (g) {
        if (ds671_read_slice(a, g, expert_id, buf + cursor)) goto fail;
        cursor += g->bytes_per_expert;
    }
    if (ds671_read_slice(a, u, expert_id, buf + cursor)) goto fail;
    cursor += u->bytes_per_expert;
    if (ds671_read_slice(a, d, expert_id, buf + cursor)) goto fail;

    *handle_out = (uint64_t)(uintptr_t)buf;
    *actual_bytes_out = total;
    return 0;
fail:
    ds671_win_free32(buf);
    return -1;
}

void ds671_adapter_release(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t handle) {
    (void)user; (void)moe_layer; (void)expert_id;
    if (handle) ds671_win_free32((void *)(uintptr_t)handle);
}

void ds671_adapter_fill_callbacks(
    ds671_callbacks *cb, ds671_tensor_adapter *adapter) {
    if (!cb) return;
    cb->measure = ds671_adapter_measure;
    cb->load = ds671_adapter_load;
    cb->release = ds671_adapter_release;
    cb->user = adapter;
}
