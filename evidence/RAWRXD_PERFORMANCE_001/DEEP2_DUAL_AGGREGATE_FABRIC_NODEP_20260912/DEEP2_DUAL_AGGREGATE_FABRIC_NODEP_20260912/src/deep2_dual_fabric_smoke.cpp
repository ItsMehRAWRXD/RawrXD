#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "deep2_dual_fabric.h"

struct Mock {
    uint32_t sleep_ms[2];
};

static int mock_submit(void* u, uint32_t gpu, const D2FabricSlice* s,
                       const void*, uint64_t, void* out, uint64_t out_bytes) {
    Mock* m = (Mock*)u;
    Sleep(m->sleep_ms[gpu]);
    if (out && out_bytes) memset(out, (int)(0x40 + gpu), (size_t)out_bytes);
    return s && s->source_bytes ? 0 : -10;
}

static int mock_reduce(void*, const void* a, const void* b, void* merged,
                       uint64_t bytes, uint32_t sum_reduce) {
    if (!a || !b || !merged) return -20;
    const uint8_t* x = (const uint8_t*)a;
    const uint8_t* y = (const uint8_t*)b;
    uint8_t* z = (uint8_t*)merged;
    for (uint64_t i = 0; i < bytes; ++i)
        z[i] = sum_reduce ? (uint8_t)(x[i] + y[i]) : (i < bytes / 2 ? x[i] : y[i]);
    return 0;
}

int main() {
    const uint64_t GB = 1000000000ull;
    Mock mock = {{40, 40}};
    D2FabricConfig cfg = {};
    cfg.bw0_bytes_per_sec = 640ull * GB;
    cfg.bw1_bytes_per_sec = 624ull * GB;
    cfg.max_reduce_bytes = 1ull << 20;
    cfg.max_broadcast_bytes = 1ull << 20;

    D2FabricBackend be = {};
    be.user = &mock;
    be.submit = mock_submit;
    be.reduce = mock_reduce;

    D2Fabric* f = d2fabric_create(&cfg, &be);
    if (!f) return 1;

    D2FabricTokenPlan p = {};
    int rc = d2fabric_plan_rows(
        f, 7, 0, 128ull << 20, 8192, D2FAB_OP_ROW_SHARD,
        16ull << 10, 64ull << 10, 0, &p);
    if (rc) return 2;

    uint8_t act[16 << 10] = {};
    uint8_t o0[64 << 10] = {};
    uint8_t o1[64 << 10] = {};
    uint8_t merged[64 << 10] = {};
    D2FabricCounters c = {};

    rc = d2fabric_execute(f, &p, act, o0, o1, merged, sizeof(merged), &c);
    const uint64_t eff = d2fabric_aggregate_effective_bps(&c);
    const uint64_t util = d2fabric_utilization_ppm(eff, 1264ull * GB);

    printf("GPU0_ROWS=%u GPU1_ROWS=%u\n", p.gpu[0].row_count, p.gpu[1].row_count);
    printf("GPU0_LOCAL_WEIGHT_BYTES=%llu\n", (unsigned long long)c.local_weight_bytes[0]);
    printf("GPU1_LOCAL_WEIGHT_BYTES=%llu\n", (unsigned long long)c.local_weight_bytes[1]);
    printf("GPU0_ACTIVE_NS=%llu GPU1_ACTIVE_NS=%llu\n",
           (unsigned long long)c.active_ns[0], (unsigned long long)c.active_ns[1]);
    printf("BOTH_LANES_WORKED=%u\n", c.both_lanes_worked);
    printf("SERIAL_GPU_CHAIN=%u\n", c.serial_gpu_chain);
    printf("WEIGHT_MIGRATION_BYTES=%llu\n", (unsigned long long)c.weight_migration_bytes);
    printf("AGGREGATE_EFFECTIVE_BPS=%llu\n", (unsigned long long)eff);
    printf("AGGREGATE_UTILIZATION_PPM=%llu\n", (unsigned long long)util);

    const int pass = (rc == 0 &&
                      c.both_lanes_worked == 1 &&
                      c.serial_gpu_chain == 0 &&
                      c.weight_migration_bytes == 0 &&
                      p.gpu[0].source_bytes > 0 &&
                      p.gpu[1].source_bytes > 0);

    printf("DUAL_FABRIC_SMOKE=%s\n", pass ? "PASS" : "FAIL");
    d2fabric_destroy(f);
    return pass ? 0 : 3;
}
