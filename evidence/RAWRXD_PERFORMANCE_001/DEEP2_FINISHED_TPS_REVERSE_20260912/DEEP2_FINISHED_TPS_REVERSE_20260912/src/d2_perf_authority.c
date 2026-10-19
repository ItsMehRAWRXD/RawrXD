#include "d2_perf_authority.h"

D2PerfProjection d2_perf_project(uint64_t touched_weight_bytes_per_token,
                                 double target_tps,
                                 double device_peak_bw_gbs) {
    D2PerfProjection r;
    const double bytes = (double)touched_weight_bytes_per_token;
    r.touched_weight_bytes_per_token = touched_weight_bytes_per_token;
    r.target_tps = target_tps;
    r.required_weight_bw_gbs = (bytes * target_tps) / 1.0e9;
    r.device_peak_bw_gbs = device_peak_bw_gbs;
    r.peak_bw_utilization = device_peak_bw_gbs > 0.0
        ? r.required_weight_bw_gbs / device_peak_bw_gbs : 0.0;
    r.ideal_weight_only_ms_per_token = device_peak_bw_gbs > 0.0
        ? (bytes / (device_peak_bw_gbs * 1.0e9)) * 1000.0 : 0.0;
    return r;
}

D2PerfObservedResult d2_perf_observe(const D2PerfObservation* obs) {
    D2PerfObservedResult r = {0.0, 0.0, 0.0, 0};
    if (!obs || obs->generated_tokens == 0 || obs->wall_ns == 0) return r;

    const double seconds = (double)obs->wall_ns / 1.0e9;
    r.measured_tps = (double)obs->generated_tokens / seconds;
    r.ms_per_token = ((double)obs->wall_ns / 1.0e6) / (double)obs->generated_tokens;
    r.effective_weight_bw_gbs = ((double)obs->touched_weight_bytes_total / 1.0e9) / seconds;

    r.authority_eligible =
        obs->full_model_decode == 1 &&
        obs->all_blocks_every_token == 1 &&
        obs->device_lost == 0 &&
        obs->allocation_count_after_warmup == 0 &&
        obs->sealed_logits_reuse_count == 0 &&
        obs->synthetic_logits_count == 0 &&
        obs->synthetic_weight_count == 0;
    return r;
}
