#include "ds671_route_load.h"
#include "ds671_tensor_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

/* Synthetic index: one MoE layer (moe0->blk3), gate+up+down, no disk I/O
   until load — load uses zero-byte measure path? Need non-zero bytes.
   Use measure/load override via fake slots + custom path that fails closed
   on missing shard — instead stub slots with bytes and intercept via
   replacing load with memory fill in this smoke. */

static int smoke_measure(void *u, uint32_t l, uint32_t e, uint64_t *b) {
    return ds671_adapter_measure(u, l, e, b);
}

static int smoke_load(void *u, uint32_t l, uint32_t e, uint64_t expect,
                      uint64_t *h, uint64_t *actual) {
    /* No real shards in unit smoke: allocate zero-filled pack. */
    void *p;
    (void)u; (void)l; (void)e;
    if (!expect || !h || !actual) return -1;
    p = _aligned_malloc((size_t)expect, 32);
    if (!p) return -1;
    memset(p, 0, (size_t)expect);
    *h = (uint64_t)(uintptr_t)p;
    *actual = expect;
    return 0;
}

static void smoke_rel(void *u, uint32_t l, uint32_t e, uint64_t h) {
    ds671_adapter_release(u, l, e, h);
}

int main(void) {
    ds671_tensor_adapter ad;
    ds671_proj_slot slots[3];
    ds671_ctx c; ds671_config cfg; ds671_callbacks cb; ds671_route_result rr;
    uint32_t ids[8] = {0,1,2,3,4,5,6,7};
    size_t n; void *arena; int rc;
    uint64_t dims_g[3] = {7168, 2048, 256};
    uint64_t bpe_g, bpe_d;
    char name[64];

    memset(&ad, 0, sizeof(ad));
    memset(slots, 0, sizeof(slots));
    ad.leading_dense = 3;
    ad.experts_per_layer = 256;
    ad.slots = slots;
    ad.slot_count = 3;

    bpe_g = ds671_ggml_bytes_per_expert(12, dims_g, 3); /* Q4_K gate/up */
    bpe_d = ds671_ggml_bytes_per_expert(14, dims_g, 3); /* Q6_K-ish elems */
    if (!bpe_g || !bpe_d) return 20;
    if (ds671_format_exps_name(name, sizeof(name), 3, DS671_PROJ_GATE)) return 21;
    if (strcmp(name, "blk.3.ffn_gate_exps.weight")) return 22;
    if (ds671_blk_from_moe(&ad, 0) != 3) return 23;

    slots[0].blk_layer = 3; slots[0].proj = DS671_PROJ_GATE;
    slots[0].num_experts = 256; slots[0].ggml_type = 12;
    slots[0].bytes_per_expert = bpe_g;
    slots[1] = slots[0]; slots[1].proj = DS671_PROJ_UP;
    slots[2] = slots[0]; slots[2].proj = DS671_PROJ_DOWN;
    slots[2].ggml_type = 14; slots[2].bytes_per_expert = bpe_d;

    cfg.moe_layers = 58; cfg.experts_per_layer = 256; cfg.top_k = 8;
    cfg.mode = DS671_MODE_GROW_NO_EVICT;
    cfg.routed_expert_budget_bytes = 64ull * 1024ull * 1024ull * 1024ull;
    cb.measure = smoke_measure; cb.load = smoke_load;
    cb.release = smoke_rel; cb.user = &ad;

    n = ds671_arena_bytes(cfg.moe_layers, cfg.experts_per_layer);
    arena = malloc(n);
    rc = ds671_init(&c, &cfg, &cb, arena, n); if (rc) return 30;
    rc = ds671_require_route(&c, 0, 0, ids, 8, &rr); if (rc) return 31;
    if (rr.loaded_now != 8) return 32;
    ds671_release_all(&c);
    free(arena);
    puts("DS671_TENSOR_ADAPTER_SMOKE=PASS");
    puts("SOURCE_WIRED=1");
    puts("RUNTIME_REACHED=0");
    return 0;
}
