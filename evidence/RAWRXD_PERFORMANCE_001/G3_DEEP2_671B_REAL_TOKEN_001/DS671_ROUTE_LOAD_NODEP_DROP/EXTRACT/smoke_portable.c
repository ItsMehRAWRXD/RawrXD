#include "ds671_route_load.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct fake_store { uint64_t next; } fake_store;

static int m(void *u, uint32_t l, uint32_t e, uint64_t *b) {
    (void)u; (void)l; (void)e; *b = 4096; return 0;
}
static int ld(void *u, uint32_t l, uint32_t e, uint64_t expect,
              uint64_t *h, uint64_t *actual) {
    fake_store *s = (fake_store*)u; (void)l; (void)e;
    *actual = expect; *h = ++s->next; return 0;
}
static void rel(void *u, uint32_t l, uint32_t e, uint64_t h) {
    (void)u; (void)l; (void)e; (void)h;
}

int main(void) {
    ds671_ctx c; ds671_config cfg; ds671_callbacks cb; ds671_route_result rr;
    fake_store fs = {100}; uint32_t ids[8] = {1,2,3,4,5,6,7,8};
    size_t n; void *arena; int rc;
    cfg.moe_layers=58; cfg.experts_per_layer=256; cfg.top_k=8;
    cfg.mode=DS671_MODE_GROW_NO_EVICT;
    cfg.routed_expert_budget_bytes=64ull*1024ull*1024ull;
    cb.measure=m; cb.load=ld; cb.release=rel; cb.user=&fs;
    n=ds671_arena_bytes(cfg.moe_layers,cfg.experts_per_layer);
    arena=malloc(n);
    rc=ds671_init(&c,&cfg,&cb,arena,n); if(rc) return 10;
    rc=ds671_require_route(&c,0,0,ids,8,&rr); if(rc) return 11;
    if(rr.loaded_now!=8 || c.loads!=8 || c.resident_bytes!=8*4096ull) return 12;
    rc=ds671_require_route(&c,1,0,ids,8,&rr); if(rc) return 13;
    if(rr.loaded_now!=0 || c.hits!=8) return 14;
    rc=ds671_seal_prompt(&c,2); if(rc) return 15;
    ids[0]=9;
    rc=ds671_require_route(&c,2,0,ids,8,&rr); if(rc) return 16;
    if(c.loads!=9) return 17;
    ds671_release_all(&c); free(arena);
    puts("DS671_ROUTE_LOAD_SMOKE=PASS");
    return 0;
}
