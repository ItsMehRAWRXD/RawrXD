#include "deep2_audit_nodep.h"
#include <string.h>

static uint64_t d2_min_u64(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t d2_max_u64(uint64_t a, uint64_t b) { return a > b ? a : b; }

extern "C" int d2_dual_submit(const D2SsVkOps* ops, const D2DeviceRange* lane0,
                               const D2DeviceRange* lane1, uint64_t token_id,
                               D2AggregateMetrics* out) {
    if (!d2_ssvk_validate(ops) || !lane0 || !lane1 || !out) return 0;
    if (lane0->gpu == lane1->gpu || lane0->bytes == 0 || lane1->bytes == 0 ||
        lane0->row_count == 0 || lane1->row_count == 0) return 0;
    if (!ops->load_exact(ops->ctx, lane0) || !ops->load_exact(ops->ctx, lane1)) return 0;

    D2SubmitTicket a{}, b{};
    D2LaneReceipt ar{}, br{};
    D2MergeReceipt mr{};
    /* Both local lanes are enqueued before either collection: same-token overlap is possible by construction. */
    if (!ops->enqueue(ops->ctx, lane0, token_id, &a)) return 0;
    if (!ops->enqueue(ops->ctx, lane1, token_id, &b)) return 0;
    if (!ops->collect(ops->ctx, &a, &ar)) return 0;
    if (!ops->collect(ops->ctx, &b, &br)) return 0;
    if (!ops->reduce(ops->ctx, &a, &b, &mr)) return 0;
    if (ar.end_ns <= ar.start_ns || br.end_ns <= br.start_ns) return 0;

    memset(out, 0, sizeof(*out));
    const uint64_t lo=d2_max_u64(ar.start_ns, br.start_ns);
    const uint64_t hi=d2_min_u64(ar.end_ns, br.end_ns);
    out->overlap_ns=hi>lo ? hi-lo : 0;
    out->critical_path_ns=d2_max_u64(ar.end_ns, br.end_ns)-d2_min_u64(ar.start_ns, br.start_ns)+mr.reduce_ns;
    out->gpu0_local_bytes=ar.local_weight_bytes;
    out->gpu1_local_bytes=br.local_weight_bytes;
    out->gpu0_real_forwards=ar.real_forwards;
    out->gpu1_real_forwards=br.real_forwards;
    out->inter_gpu_bytes=mr.inter_gpu_bytes;
    out->overlap_measured=out->overlap_ns ? 1u : 0u;
    out->serial_chain=out->overlap_ns ? 0u : 1u;
    out->device_lost=(ar.device_lost || br.device_lost) ? 1u : 0u;
    out->synthetic_io=(ar.synthetic_io || br.synthetic_io) ? 1u : 0u;
    out->compact_merge_real=mr.compact_merge_real;
    const uint64_t bytes=out->gpu0_local_bytes+out->gpu1_local_bytes;
    out->aggregate_effective_bps=out->critical_path_ns ? (bytes*1000000000ull)/out->critical_path_ns : 0;
    return 1;
}

extern "C" int d2_aggregate_authoritative(const D2AggregateMetrics* m,
                                           uint32_t product_linked, uint32_t q2k_real,
                                           uint32_t deviceio_real) {
    if (!m || !product_linked || !q2k_real || !deviceio_real) return 0;
    if (!m->overlap_measured || !m->overlap_ns || m->serial_chain) return 0;
    if (!m->gpu0_real_forwards || !m->gpu1_real_forwards) return 0;
    if (!m->gpu0_local_bytes || !m->gpu1_local_bytes) return 0;
    if (m->inter_gpu_bytes || m->device_lost || m->synthetic_io) return 0;
    if (!m->compact_merge_real || !m->critical_path_ns || !m->aggregate_effective_bps) return 0;
    return 1;
}
