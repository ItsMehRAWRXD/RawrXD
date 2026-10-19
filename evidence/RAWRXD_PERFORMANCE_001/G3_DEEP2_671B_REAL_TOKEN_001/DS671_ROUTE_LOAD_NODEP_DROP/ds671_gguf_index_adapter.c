/* ds671_gguf_index_adapter.c — measure/load/release for route-load hotpatch
 * Maps (moe_layer, expert_id) -> stacked blk.{L}.ffn_{gate,up,down}_exps slices
 * via a caller-supplied tensor table (no filesystem scan inside route-load).
 * SOURCE_WIRED proof only until Deep2 live bind fills the table from GGUF. */
#include "../DS671_ROUTE_LOAD_NODEP_DROP/EXTRACT/ds671_route_load.h"
#include <string.h>
#include <stdint.h>

#define DS671_ADAPTER_MAX_TENSORS 2048

typedef struct {
    uint32_t layer;      /* transformer layer id (0..60) */
    uint32_t kind;       /* 0=gate 1=up 2=down stacked exps */
    uint64_t file_off;   /* absolute file offset of tensor data */
    uint64_t nbytes;     /* full stacked tensor bytes */
    uint32_t n_experts;  /* 256 */
    uint32_t shard;      /* shard index for multi-file */
} Ds671TensorRow;

typedef struct {
    Ds671TensorRow rows[DS671_ADAPTER_MAX_TENSORS];
    uint32_t nrow;
    uint32_t leading_dense; /* 3 */
    /* load arena: caller provides; we only record logical handles = pack id */
    uint64_t next_handle;
    int (*map_bytes)(void *u, uint32_t shard, uint64_t off, uint64_t n, uint64_t *h);
    void (*unmap_bytes)(void *u, uint64_t h);
    void *map_user;
} Ds671Index;

static int find_row(const Ds671Index *ix, uint32_t layer, uint32_t kind) {
    uint32_t i;
    for (i = 0; i < ix->nrow; i++)
        if (ix->rows[i].layer == layer && ix->rows[i].kind == kind) return (int)i;
    return -1;
}

/* moe_layer 0..57 -> transformer layer = moe_layer + leading_dense */
static uint32_t xf_layer(const Ds671Index *ix, uint32_t moe_layer) {
    return moe_layer + ix->leading_dense;
}

int ds671_index_measure(
    void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t *bytes_out) {
    Ds671Index *ix = (Ds671Index *)user;
    uint32_t L;
    int g, u, d;
    uint64_t per;
    if (!ix || !bytes_out || expert_id >= 256) return DS671_E_ARG;
    L = xf_layer(ix, moe_layer);
    g = find_row(ix, L, 0); u = find_row(ix, L, 1); d = find_row(ix, L, 2);
    if (g < 0 || u < 0 || d < 0) return DS671_E_RANGE;
    /* equal split of stacked expert packs (fail closed if not divisible) */
    if (ix->rows[g].nbytes % 256 || ix->rows[u].nbytes % 256 || ix->rows[d].nbytes % 256)
        return DS671_E_SIZE_MISMATCH;
    per = ix->rows[g].nbytes / 256 + ix->rows[u].nbytes / 256 + ix->rows[d].nbytes / 256;
    *bytes_out = per;
    return DS671_OK;
}

int ds671_index_load(
    void *user, uint32_t moe_layer, uint32_t expert_id,
    uint64_t expected_bytes, uint64_t *handle_out, uint64_t *actual_bytes_out) {
    Ds671Index *ix = (Ds671Index *)user;
    uint64_t need = 0, h = 0;
    int rc;
    if (!ix || !handle_out || !actual_bytes_out) return DS671_E_ARG;
    rc = ds671_index_measure(user, moe_layer, expert_id, &need);
    if (rc != DS671_OK) return rc;
    if (need != expected_bytes) return DS671_E_SIZE_MISMATCH;
    if (!ix->map_bytes) {
        /* logical handle only — proves dispatch without I/O */
        h = ++ix->next_handle;
    } else {
        /* Real map of three slices would go here; keep fail-closed if mapper unset path used wrong */
        return DS671_E_LOAD;
    }
    *handle_out = h;
    *actual_bytes_out = need;
    (void)moe_layer; (void)expert_id;
    return DS671_OK;
}

void ds671_index_release(void *user, uint32_t moe_layer, uint32_t expert_id, uint64_t handle) {
    Ds671Index *ix = (Ds671Index *)user;
    if (ix && ix->unmap_bytes) ix->unmap_bytes(ix->map_user, handle);
    (void)moe_layer; (void)expert_id;
}
