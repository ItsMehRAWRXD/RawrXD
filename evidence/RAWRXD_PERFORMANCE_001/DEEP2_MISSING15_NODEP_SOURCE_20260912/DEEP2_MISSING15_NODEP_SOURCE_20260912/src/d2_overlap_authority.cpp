#include "d2_nodep.h"
#include <algorithm>

extern "C" int d2_measure_overlap(const D2LaneReceipt* a, const D2LaneReceipt* b, const D2ReduceReceipt* r, D2FabricMetrics* out) {
    if (!a || !b || !r || !out) return 0;
    if (a->end_ns <= a->start_ns || b->end_ns <= b->start_ns) return 0;
    const uint64_t lo = std::max(a->start_ns, b->start_ns);
    const uint64_t hi = std::min(a->end_ns, b->end_ns);
    const uint64_t overlap = hi > lo ? hi - lo : 0;
    const uint64_t start = std::min(a->start_ns, b->start_ns);
    const uint64_t end = std::max(a->end_ns, b->end_ns);
    const uint64_t cp = (end - start) + r->reduce_ns;
    const uint64_t bytes = a->local_weight_bytes + b->local_weight_bytes;
    *out = {};
    out->overlap_ns = overlap;
    out->critical_path_ns = cp;
    out->aggregate_effective_bps = cp ? (bytes * 1000000000ull) / cp : 0;
    out->gpu0_real_forwards = a->real_forwards;
    out->gpu1_real_forwards = b->real_forwards;
    out->gpu0_local_bytes = a->local_weight_bytes;
    out->gpu1_local_bytes = b->local_weight_bytes;
    out->inter_gpu_bytes = r->inter_gpu_bytes;
    out->overlap_ratio_measured = overlap > 0 ? 1u : 0u;
    out->serial_gpu_chain = overlap == 0 ? 1u : 0u;
    out->weight_migration_bytes_nonzero = r->inter_gpu_bytes > 0 ? 1u : 0u;
    out->device_lost = (a->device_lost || b->device_lost) ? 1u : 0u;
    out->synthetic_device_io = (a->synthetic_device_io || b->synthetic_device_io) ? 1u : 0u;
    out->compact_merge_real = r->compact_merge_real;
    return 1;
}
