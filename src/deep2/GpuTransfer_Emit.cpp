// GpuTransfer_Emit.cpp — snapshot + emit for GPU_TRANSFER_*
#include "GpuTransferCounters.hpp"
#include <unordered_set>

namespace Deep2 {

namespace {
std::unordered_set<uintptr_t> g_seenKeys;
}

bool GpuTransfer_MarkSeenKey(uintptr_t key) {
    return g_seenKeys.insert(key).second;
}

void GpuTransfer_ResetSeenKeys() { g_seenKeys.clear(); }

GpuTransferSnapshot GpuTransfer_Snapshot() {
    GpuTransferSnapshot s;
    s.copyBytes = GTC_bytes().load(); s.copyOps = GTC_ops().load();
    s.weightBytes = GTC_weight().load(); s.actBytes = GTC_act().load();
    s.waitUs = GTC_waitUs().load(); s.submitUs = GTC_submitUs().load();
    s.overlapUs = GTC_overlapUs().load();
    s.overlapEvents = GTC_overlapEv().load(); s.overlapBytes = GTC_overlapB().load();
    s.tokens = GTC_tokens().load(); s.layers = GTC_layers().load();
    s.fwdLayers = GTC_fwdLayers().load();
    s.weightHits = GTC_wHits().load(); s.weightMisses = GTC_wMiss().load();
    s.weightHitBytes = GTC_wHitB().load();
    s.firstLoadBytes = GTC_firstB().load(); s.reloadBytes = GTC_reloadB().load();
    s.slotReuses = GTC_slotReuse().load(); s.redundantUploads = GTC_redundant().load();
    return s;
}

void GpuTransfer_Emit(FILE* f) {
    if (!f) f = stdout;
    auto s = GpuTransfer_Snapshot();
    const uint64_t layerDen = s.fwdLayers ? s.fwdLayers : s.layers;
    const double bpt = s.tokens ? (double)s.copyBytes / (double)s.tokens : 0.0;
    const double bpl = layerDen ? (double)s.copyBytes / (double)layerDen : 0.0;
    fprintf(f, "GPU_COPY_BYTES_TOTAL=%llu\n", (unsigned long long)s.copyBytes);
    fprintf(f, "GPU_COPY_OPS_TOTAL=%llu\n", (unsigned long long)s.copyOps);
    fprintf(f, "GPU_WEIGHT_BYTES_TOTAL=%llu\n", (unsigned long long)s.weightBytes);
    fprintf(f, "GPU_ACTIVATION_BYTES_TOTAL=%llu\n", (unsigned long long)s.actBytes);
    fprintf(f, "GPU_COPY_BYTES_PER_TOKEN=%.1f\n", bpt);
    fprintf(f, "GPU_COPY_BYTES_PER_LAYER=%.1f\n", bpl);
    fprintf(f, "GPU_COPY_LAYER_DENOM=%llu\n", (unsigned long long)layerDen);
    fprintf(f, "GPU_COPY_WAIT_US=%llu\n", (unsigned long long)s.waitUs);
    fprintf(f, "GPU_COPY_SUBMIT_US=%llu\n", (unsigned long long)s.submitUs);
    fprintf(f, "GPU_COPY_OVERLAP_US=%llu\n", (unsigned long long)s.overlapUs);
    fprintf(f, "GPU_COPY_OVERLAP_EVENTS=%llu\n", (unsigned long long)s.overlapEvents);
    fprintf(f, "GPU_COPY_OVERLAP_BYTES=%llu\n", (unsigned long long)s.overlapBytes);
    fprintf(f, "GPU_WEIGHT_CACHE_HITS=%llu\n", (unsigned long long)s.weightHits);
    fprintf(f, "GPU_WEIGHT_CACHE_MISSES=%llu\n", (unsigned long long)s.weightMisses);
    fprintf(f, "GPU_WEIGHT_BYTES_ALREADY_LOCAL=%llu\n",
            (unsigned long long)s.weightHitBytes);
    fprintf(f, "GPU_WEIGHT_BYTES_FIRST_LOAD=%llu\n", (unsigned long long)s.firstLoadBytes);
    fprintf(f, "GPU_WEIGHT_BYTES_RELOAD=%llu\n", (unsigned long long)s.reloadBytes);
    fprintf(f, "GPU_WEIGHT_SLOT_REUSES=%llu\n", (unsigned long long)s.slotReuses);
    fprintf(f, "GPU_WEIGHT_REDUNDANT_UPLOADS=%llu\n", (unsigned long long)s.redundantUploads);
    fflush(f);
}

} // namespace Deep2
