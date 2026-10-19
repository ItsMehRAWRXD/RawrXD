#include "ds671_gguf_index.h"
#include "ds671_tensor_adapter.h"
#include <stdio.h>
#include <string.h>

/* Index-only: scan shard-00001, resolve blk.3 gate/up/down. No expert I/O. */
int main(void) {
    static ds671_proj_slot slots[512];
    ds671_tensor_adapter ad;
    const char *path =
        "F:/OllamaModels/DeepSeek-R1-Q4_K_M-COMPLETE/"
        "DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    const char *paths[1];
    uint32_t n = 0;
    uint64_t data_off = 0;
    const ds671_proj_slot *g, *u, *d;
    int rc;

    paths[0] = path;
    memset(&ad, 0, sizeof(ad));
    ad.shard_paths = paths;
    ad.shard_count = 1;
    ad.slots = slots;
    ad.leading_dense = 3;
    ad.experts_per_layer = 256;

    rc = ds671_gguf_scan_shard_exps(path, 0, slots, 512, &n, &data_off);
    if (rc) { printf("SCAN_RC=%d\n", rc); return 1; }
    ad.slot_count = n;
    g = ds671_find_proj(&ad, 3, DS671_PROJ_GATE);
    u = ds671_find_proj(&ad, 3, DS671_PROJ_UP);
    d = ds671_find_proj(&ad, 3, DS671_PROJ_DOWN);
    if (!g || !u || !d) return 2;
    if (g->num_experts != 256 || u->num_experts != 256 || d->num_experts != 256)
        return 3;
    if (!g->bytes_per_expert || !u->bytes_per_expert || !d->bytes_per_expert)
        return 4;
    printf("SLOTS=%u DATA_OFF=%llu\n", n, (unsigned long long)data_off);
    printf("BLK3_GATE_BPE=%llu UP=%llu DOWN=%llu\n",
           (unsigned long long)g->bytes_per_expert,
           (unsigned long long)u->bytes_per_expert,
           (unsigned long long)d->bytes_per_expert);
    puts("DS671_GGUF_INDEX_BIND=PASS");
    puts("SOURCE_WIRED=1");
    puts("RUNTIME_REACHED=0");
    return 0;
}
