#include "../include/d2_material_overlap.h"
#include <string.h>

static uint64_t u64_min(uint64_t a, uint64_t b) { return a < b ? a : b; }
static uint64_t u64_max(uint64_t a, uint64_t b) { return a > b ? a : b; }

extern "C" int32_t D2_CALL d2_overlap_evaluate(
    const D2ProductProof* proof,
    const D2OverlapPolicy* policy,
    D2OverlapReceipt* r) {
    if (!proof || !policy || !r) return -1;

    r->product_linked = proof->product_linked ? 1u : 0u;
    r->packed_q2k_live = proof->packed_q2k_live ? 1u : 0u;
    r->full_dequant_buffer = proof->full_dequant_buffer ? 1u : 0u;
    r->materialized_weight_bytes = proof->materialized_weight_bytes;
    r->weight_migration_bytes = proof->weight_migration_bytes;
    r->synthetic_device_io = proof->synthetic_device_io ? 1u : 0u;
    r->serial_gpu_chain = proof->serial_gpu_chain ? 1u : 0u;
    r->critical_path_nvme_reads = proof->critical_path_nvme_reads;
    r->promote = 0;
    r->aggregate_bw_authority = 0; /* single-token path never mints authority */

    const uint64_t s0 = r->lane[0].mapped_start_ns;
    const uint64_t e0 = r->lane[0].mapped_end_ns;
    const uint64_t s1 = r->lane[1].mapped_start_ns;
    const uint64_t e1 = r->lane[1].mapped_end_ns;
    if (e0 <= s0 || e1 <= s1) { r->rc = -2; return r->rc; }

    r->lane[0].duration_ns = e0 - s0;
    r->lane[1].duration_ns = e1 - s1;
    const uint64_t os = u64_max(s0, s1);
    const uint64_t oe = u64_min(e0, e1);
    r->overlap_ns = oe > os ? oe - os : 0;
    const uint64_t cs = u64_min(s0, s1);
    const uint64_t ce = u64_max(e0, e1);
    r->critical_path_ns = ce > cs ? ce - cs : 0;

    const uint64_t shorter = u64_min(r->lane[0].duration_ns, r->lane[1].duration_ns);
    r->shorter_overlap_permille = shorter ? (uint32_t)((r->overlap_ns * 1000ull) / shorter) : 0;
    r->critical_overlap_permille = r->critical_path_ns ? (uint32_t)((r->overlap_ns * 1000ull) / r->critical_path_ns) : 0;
    r->aggregate_packed_bytes = r->lane[0].packed_bytes + r->lane[1].packed_bytes;
    r->aggregate_effective_bps = r->critical_path_ns ? (r->aggregate_packed_bytes * 1000000000ull) / r->critical_path_ns : 0;

    r->dual_gpu_real_forwards =
        (r->lane[0].record_rc == 0 && r->lane[1].record_rc == 0 &&
         r->lane[0].submit_rc == D2_VK_SUCCESS && r->lane[1].submit_rc == D2_VK_SUCCESS &&
         r->lane[0].wait_rc == D2_VK_SUCCESS && r->lane[1].wait_rc == D2_VK_SUCCESS &&
         r->lane[0].packed_bytes >= policy->min_packed_bytes_per_lane &&
         r->lane[1].packed_bytes >= policy->min_packed_bytes_per_lane) ? 1u : 0u;

    const uint32_t calibrated =
        (r->lane[0].calibrate_rc == D2_VK_SUCCESS && r->lane[1].calibrate_rc == D2_VK_SUCCESS &&
         r->lane[0].calibration_deviation_ns <= policy->max_calibration_deviation_ns &&
         r->lane[1].calibration_deviation_ns <= policy->max_calibration_deviation_ns) ? 1u : 0u;

    r->material_same_token_overlap =
        (calibrated && r->dual_gpu_real_forwards &&
         r->shorter_overlap_permille >= policy->min_shorter_overlap_permille &&
         r->critical_overlap_permille >= policy->min_critical_overlap_permille) ? 1u : 0u;

    /* Per-token candidate. Repeated-token window is the only authority minter. */
    r->aggregate_bw_candidate =
        (r->product_linked && r->packed_q2k_live &&
         r->full_dequant_buffer == 0 && r->materialized_weight_bytes == 0 &&
         r->weight_migration_bytes == 0 && r->synthetic_device_io == 0 &&
         r->serial_gpu_chain == 0 && r->critical_path_nvme_reads == 0 &&
         r->compact_reduce_real && r->material_same_token_overlap) ? 1u : 0u;

    r->rc = 0;
    return 0;
}

extern "C" int32_t D2_CALL d2_overlap_window_evaluate(
    const D2OverlapReceipt* receipts,
    uint32_t n,
    const D2OverlapWindowPolicy* policy,
    D2OverlapWindowReceipt* w) {
    if (!receipts || !policy || !w || n == 0) return -1;
    memset(w, 0, sizeof(*w));
    w->promote = 0;
    w->token_count = n;
    w->min_shorter_overlap_permille_seen = 0xffffffffu;
    w->min_critical_overlap_permille_seen = 0xffffffffu;

    for (uint32_t i=0; i<n; ++i) {
        const D2OverlapReceipt* r = &receipts[i];
        if (r->rc != 0) { w->rc = -2; w->aggregate_bw_authority = 0; return w->rc; }
        if (r->aggregate_bw_candidate) ++w->candidate_pass_count;
        if (r->shorter_overlap_permille < w->min_shorter_overlap_permille_seen)
            w->min_shorter_overlap_permille_seen = r->shorter_overlap_permille;
        if (r->critical_overlap_permille < w->min_critical_overlap_permille_seen)
            w->min_critical_overlap_permille_seen = r->critical_overlap_permille;
        w->total_packed_bytes += r->aggregate_packed_bytes;
        w->total_critical_path_ns += r->critical_path_ns;
    }
    w->candidate_pass_permille = (uint32_t)(((uint64_t)w->candidate_pass_count * 1000ull) / n);
    w->aggregate_effective_bps = w->total_critical_path_ns
        ? (w->total_packed_bytes * 1000000000ull) / w->total_critical_path_ns : 0;
    w->aggregate_bw_authority =
        (n >= policy->min_repeated_tokens &&
         w->candidate_pass_permille >= policy->min_candidate_pass_permille) ? 1u : 0u;
    w->rc = 0;
    return 0;
}
