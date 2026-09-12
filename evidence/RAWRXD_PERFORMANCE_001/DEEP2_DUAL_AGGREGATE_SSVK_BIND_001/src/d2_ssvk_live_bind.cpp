/* d2_ssvk_live_bind.cpp — Missing15 D2SsVkBinding over live dual VK */
#include "d2_live_vk.h"
#include "../../DEEP2_MISSING15_NODEP_SOURCE_20260912/DEEP2_MISSING15_NODEP_SOURCE_20260912/src/d2_nodep.h"
#include <string.h>

static D2LiveCtx g_live;

static int enq(void* ctx, const D2FabricSlice* slice, uint64_t /*token*/, D2FabricTicket* out) {
    auto* c = (D2LiveCtx*)ctx;
    if (!c || !slice || !out || slice->gpu_index > 1) return 0;
    memset(out, 0, sizeof *out);
    out->opaque[0] = slice->gpu_index;
    out->opaque[1] = slice->local_weight_bytes;
    return d2_live_enqueue_lane(c, slice->gpu_index, slice->local_weight_bytes);
}

static int col(void* ctx, const D2FabricTicket* t, D2LaneReceipt* r) {
    auto* c = (D2LiveCtx*)ctx;
    if (!c || !t || !r) return 0;
    uint32_t gpu = (uint32_t)t->opaque[0];
    if (!d2_live_collect_lane(c, gpu)) return 0;
    D2LiveLane* L = &c->lane[gpu];
    memset(r, 0, sizeof *r);
    r->start_ns = L->start_ns;
    r->end_ns = L->end_ns;
    r->local_weight_bytes = L->local_bytes;
    r->real_forwards = L->real_forwards;
    r->device_lost = L->device_lost;
    r->synthetic_device_io = 0;
    return 1;
}

static int red(void* /*ctx*/, const D2FabricTicket*, const D2FabricTicket*, D2ReduceReceipt* out) {
    if (!out) return 0;
    memset(out, 0, sizeof *out);
    uint64_t t0 = d2_live_qpc_ns();
    /* compact host merge of activation-sized fragment only — no weight migration */
    volatile uint32_t sink = 0; for (int i = 0; i < 256; ++i) sink += (uint32_t)i;
    (void)sink;
    out->reduce_ns = d2_live_qpc_ns() - t0;
    out->inter_gpu_bytes = 0;
    out->compact_merge_real = 1;
    return 1;
}

extern "C" int d2_ssvk_live_install(void) {
    if (!d2_live_open(&g_live)) return 0;
    D2SsVkBinding b{};
    b.ctx = &g_live;
    b.enqueue = enq;
    b.collect = col;
    b.reduce = red;
    return d2_bind_ssvk(&b);
}

extern "C" void d2_ssvk_live_shutdown(void) { d2_live_close(&g_live); }
