#include <stdio.h>
#include <string.h>
#include "d2_runtime.h"

static uint64_t loaded[2];
static int fake_load(void *ctx, uint32_t d, const D2ByteRange *r, uint64_t ticket) {
    (void)ctx;
    (void)ticket;
    if (!r || d >= D2_MAX_DEVICES) return D2_EINVAL;
    loaded[d] += r->bytes;
    return D2_OK;
}

int main(void) {
    D2Runtime rt;
    D2DeviceIo io;
    D2PlacementCost cost = {{20, 28}, {10, 12}, 15};
    D2ExpertTensorSet sets[3];
    D2TokenPlan p;
    uint32_t selected[3] = {7, 11, 31};
    size_t i, j;

    memset(&io, 0, sizeof(io));
    io.load_exact = fake_load;
    /* GPU0 is the fast 16 MiB tier; GPU1 is the larger 32 MiB tier in this smoke. */
    d2_runtime_init(&rt, &io, 16ULL << 20, 32ULL << 20, 640ULL << 30, 624ULL << 30);
    memset(sets, 0, sizeof(sets));

    for (i = 0; i < 2; ++i) {
        sets[i].expert_id = (uint32_t)(i == 0 ? 7 : 11);
        sets[i].range_count = 3;
        for (j = 0; j < 3; ++j) {
            sets[i].ranges[j].shard = (uint32_t)i;
            sets[i].ranges[j].codec = 4;
            sets[i].ranges[j].offset = (uint64_t)j * (2ULL << 20);
            sets[i].ranges[j].bytes = 2ULL << 20;
            sets[i].ranges[j].tensor_id = 1000 + i * 10 + j;
            sets[i].ranges[j].expert_id = sets[i].expert_id;
            sets[i].ranges[j].role = (uint32_t)j;
        }
    }

    /* One tensor cannot fit GPU0 at all; placement must select GPU1. */
    sets[2].expert_id = 31;
    sets[2].range_count = 1;
    sets[2].ranges[0].shard = 2;
    sets[2].ranges[0].codec = 4;
    sets[2].ranges[0].offset = 0;
    sets[2].ranges[0].bytes = 20ULL << 20;
    sets[2].ranges[0].tensor_id = 1030;
    sets[2].ranges[0].expert_id = 31;
    sets[2].ranges[0].role = 0;

    if (d2_plan_token(&rt.residency, &rt.locality, 0, selected, 3, sets, 3, &cost, &p) != D2_OK) return 10;
    if (p.count != 7) return 11;
    if (p.bytes_by_device[0] == 0 || p.bytes_by_device[1] == 0) return 12;
    if (d2_runtime_stage_plan(&rt, &p) != D2_OK) return 13;
    while (rt.stream.count) {
        if (d2_runtime_pump_one(&rt, 0) != D2_OK) return 14;
    }
    if (loaded[0] == 0 || loaded[1] == 0) return 15;

    /* Same router selection: all exact tensors are already resident, so no new I/O. */
    if (d2_plan_token(&rt.residency, &rt.locality, 1, selected, 3, sets, 3, &cost, &p) != D2_OK) return 16;
    if (d2_runtime_stage_plan(&rt, &p) != D2_OK) return 17;
    if (rt.stream.count != 0) return 18;
    if (rt.residency.counters.exact_range_requests != 7) return 19;

    printf("DEEP2_LOCALITY_STREAM_DUALGPU_SMOKE=PASS\n");
    printf("EXACT_RANGE_REQUESTS=%llu\n", (unsigned long long)rt.residency.counters.exact_range_requests);
    printf("GPU0_LOADED=%llu GPU1_LOADED=%llu\n", (unsigned long long)loaded[0], (unsigned long long)loaded[1]);
    printf("GPU0_USED=%llu GPU1_USED=%llu\n", (unsigned long long)rt.residency.dev[0].used_bytes, (unsigned long long)rt.residency.dev[1].used_bytes);
    printf("DUAL_GPU_NONZERO=%u\n", (loaded[0] && loaded[1]) ? 1u : 0u);
    printf("SEALED_LOGITS_REUSE_COUNT=0\n");
    printf("PROMOTE=0\n");
    return 0;
}
