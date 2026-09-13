/* MoEPlaceLiveCounters.cpp — emit place + DualStick reuse microfix. */
#include "MoEPlaceLiveCounters.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include <cstring>

namespace Deep2 {

MoEPlaceLiveCounters& MoEPlaceLive() {
    static MoEPlaceLiveCounters g{};
    return g;
}

void MoEPlaceLiveReset() {
    std::memset(&MoEPlaceLive(), 0, sizeof(MoEPlaceLiveCounters));
}

void MoEPlaceLiveEmit(FILE* f) {
    if (!f) return;
    const MoEPlaceLiveCounters& c = MoEPlaceLive();
    std::fprintf(f,
        "D2_MOE_LIVE moe_ffn_enter=%llu moe_place_enter=%llu "
        "MOE_PLACE_CALLS=%llu moe_router_calls=%llu "
        "ffn_dispatch_moe=%llu ffn_dispatch_dense=%llu ffn_dispatch_ssm=%llu\n"
        "D2_MOE_LIVE experts_selected=%llu experts_executed=%llu "
        "parity=%d thrash_tokens=%llu\n",
        (unsigned long long)c.moe_ffn_enter,
        (unsigned long long)c.moe_place_enter,
        (unsigned long long)c.moe_place_calls,
        (unsigned long long)c.moe_router_calls,
        (unsigned long long)c.ffn_dispatch_moe,
        (unsigned long long)c.ffn_dispatch_dense,
        (unsigned long long)c.ffn_dispatch_ssm,
        (unsigned long long)c.experts_selected,
        (unsigned long long)c.experts_executed,
        (c.experts_selected == c.experts_executed) ? 1 : 0,
        (unsigned long long)c.moe_thrash_tokens);
    if (c.moe_place_enter == 0) {
        std::fprintf(f,
            "D2_MOE_LIVE hits=N/A misses=N/A miss_bytes=N/A "
            "EXPERT_LOGICAL_MISS_BYTES=N/A_NOT_REACHED "
            "acquire_ok=%llu acquire_fail=%llu markhot=%llu\n",
            (unsigned long long)c.expert_acquire_ok,
            (unsigned long long)c.expert_acquire_fail,
            (unsigned long long)c.expert_markhot);
    } else {
        const uint64_t tok = c.moe_tokens ? c.moe_tokens : 1ull;
        std::fprintf(f,
            "D2_MOE_LIVE hits=%llu misses=%llu EXPERT_LOGICAL_MISS_BYTES=%llu "
            "EXPERT_MISS_BYTES_PER_PLACE_ENTER=%llu_NONAUTH acquire_ok=%llu "
            "acquire_fail=%llu markhot=%llu\n",
            (unsigned long long)c.expert_cache_hits,
            (unsigned long long)c.expert_cache_misses,
            (unsigned long long)c.expert_miss_bytes,
            (unsigned long long)(c.expert_miss_bytes / tok),
            (unsigned long long)c.expert_acquire_ok,
            (unsigned long long)c.expert_acquire_fail,
            (unsigned long long)c.expert_markhot);
        const uint64_t rld = c.reload_miss_bytes / tok;
        const uint64_t genTok =
            c.stream_generated_tokens ? c.stream_generated_tokens : 1ull;
        const uint64_t layerDen = c.moe_layers_gpu ? c.moe_layers_gpu : 1ull;
        std::fprintf(f,
            "D2_MOE_REUSE EXPERT_BUNDLE_LOOKUPS=%llu HITS=%llu MISSES=%llu "
            "EXPERT_ACQUIRE_HIT=%llu EXPERT_ACQUIRE_MISS=%llu "
            "HOST_BYTES_FOR_HIT=%llu HOST_BYTES_FOR_MISS=%llu "
            "SECONDARY_LOOKUP=%llu\n"
            "D2_MOE_REUSE COMPULSORY_MISS_BYTES=%llu RELOAD_MISS_BYTES=%llu "
            "HIT_BYTES=%llu RELOAD_MISS_BYTES_PER_PLACE_ENTER=%llu_NONAUTH "
            "SEEN_BUNDLE_KEYS=%llu\n"
            "D2_MOE_BYTES EXPERT_H2D_BYTES=%llu EXPERT_H2D_BYTES_PER_GENERATED_TOKEN=%llu "
            "EXPERT_H2D_BYTES_PER_MOE_LAYER=%llu RELOAD_MISS_BYTES_PER_GENERATED_TOKEN=%llu "
            "STREAM_GENERATED_TOKENS=%llu\n"
            "D2_MOE_REUSE GPU0_EXPERTS=%llu GPU1_EXPERTS=%llu "
            "GPU0_WORK_NS=%llu GPU1_WORK_NS=%llu GPU_JOIN_WAIT_NS=%llu "
            "STICK_OVERLAP_NS=%llu H2D_BYTES=%llu D2H_BYTES=%llu "
            "GPU_SUBMITS=%llu GPU_WAITS=%llu MOE_LAYERS_GPU=%llu "
            "GPU_SUBMITS_PER_MOE_LAYER=%llu GPU_WAITS_PER_MOE_LAYER=%llu "
            "DEVICE_DOWN_PARTIALS=%llu GEMV_INPUT_REUSE=%llu "
            "DEVICE_DOWN_VECTORS=%llu DEVICE_PARTIAL_ACCUMS=%llu "
            "D2H_PARTIAL_VECTORS=%llu HOST_EXPERT_DOWN_VECTORS=%llu "
            "INTERMEDIATE_D2H=%llu EXPERT_D2H=%llu "
            "STICK_OVERLAP_NS=%llu MAX_CONCURRENT_STICK_WORKERS=%llu "
            "LAYER_JOINS=%llu WORKER_FAILURES=%llu "
            "PRODUCT_BACKEND_ATTESTED=%llu\n"
            "D2_MOE_REUSE HOST_EXPERT_GEMV_CALLS=%llu "
            "GPU_EXPERT_GEMV_CALLS=%llu\n"
            "D2_MOE_IMBALANCE STICK_SKEW_NS=%llu STICK_COMPLETION_SKEW_PCT=%llu "
            "PREDICTED_VS_ACTUAL_ERROR_PCT=%llu "
            "PREDICT_ERR_KERNEL_PCT=%llu PREDICT_ERR_XFER_PCT=%llu "
            "PREDICT_ERR_QUEUE_PCT=%llu "
            "GPU0_IDLE_AT_JOIN_NS=%llu GPU1_IDLE_AT_JOIN_NS=%llu "
            "MIGRATIONS=%llu WORK_STEALS=%llu "
            "RESIDENCY_LOST_TO_REBALANCE_BYTES=%llu\n",
            (unsigned long long)c.expert_bundle_lookups,
            (unsigned long long)c.expert_bundle_hits,
            (unsigned long long)c.expert_bundle_misses,
            (unsigned long long)c.expert_acquire_hits,
            (unsigned long long)c.expert_acquire_misses,
            (unsigned long long)c.host_bytes_for_hit,
            (unsigned long long)c.host_bytes_for_miss,
            (unsigned long long)c.secondary_lookup,
            (unsigned long long)c.compulsory_miss_bytes,
            (unsigned long long)c.reload_miss_bytes,
            (unsigned long long)c.hit_bytes, (unsigned long long)rld,
            (unsigned long long)c.seen_bundle_keys,
            (unsigned long long)c.h2d_bytes,
            (unsigned long long)(c.h2d_bytes / genTok),
            (unsigned long long)(c.h2d_bytes / layerDen),
            (unsigned long long)(c.reload_miss_bytes / genTok),
            (unsigned long long)c.stream_generated_tokens,
            (unsigned long long)c.gpu0_experts,
            (unsigned long long)c.gpu1_experts,
            (unsigned long long)c.gpu0_work_ns,
            (unsigned long long)c.gpu1_work_ns,
            (unsigned long long)c.gpu_join_wait_ns,
            (unsigned long long)c.stick_overlap_ns,
            (unsigned long long)c.h2d_bytes, (unsigned long long)c.d2h_bytes,
            (unsigned long long)c.gpu_submits, (unsigned long long)c.gpu_waits,
            (unsigned long long)c.moe_layers_gpu,
            (unsigned long long)(c.moe_layers_gpu
                                    ? c.gpu_submits / c.moe_layers_gpu
                                    : 0ull),
            (unsigned long long)(c.moe_layers_gpu
                                    ? c.gpu_waits / c.moe_layers_gpu
                                    : 0ull),
            (unsigned long long)c.device_down_partials,
            (unsigned long long)c.gemv_input_reuse,
            (unsigned long long)c.device_down_vectors,
            (unsigned long long)c.device_partial_accums,
            (unsigned long long)c.d2h_partial_vectors,
            (unsigned long long)c.host_expert_down_vectors,
            0ull, /* INTERMEDIATE_D2H: device partial path keeps mid-D2H=0 */
            (unsigned long long)c.host_expert_down_vectors, /* EXPERT_D2H */
            (unsigned long long)c.stick_overlap_ns,
            (unsigned long long)c.max_concurrent_stick_workers,
            (unsigned long long)c.layer_joins,
            (unsigned long long)c.worker_failures,
            (unsigned long long)c.product_backend_attested,
            (unsigned long long)c.host_gemv_expert,
            (unsigned long long)c.expert_gpu_exec,
            (unsigned long long)c.stick_skew_ns,
            (unsigned long long)(c.stick_skew_samples
                                    ? (c.stick_skew_pct_sum_x100 /
                                       c.stick_skew_samples) /
                                          100ull
                                    : 0ull),
            (unsigned long long)(c.pred_actual_sum_ns
                                    ? (c.pred_err_sum_ns * 100ull) /
                                          c.pred_actual_sum_ns
                                    : 0ull),
            (unsigned long long)(c.pred_actual_sum_ns
                                    ? (c.pred_err_kernel_ns * 100ull) /
                                          c.pred_actual_sum_ns
                                    : 0ull),
            (unsigned long long)(c.pred_actual_sum_ns
                                    ? (c.pred_err_xfer_ns * 100ull) /
                                          c.pred_actual_sum_ns
                                    : 0ull),
            (unsigned long long)(c.pred_actual_sum_ns
                                    ? (c.pred_err_queue_ns * 100ull) /
                                          c.pred_actual_sum_ns
                                    : 0ull),
            (unsigned long long)c.gpu0_idle_at_join_ns,
            (unsigned long long)c.gpu1_idle_at_join_ns,
            (unsigned long long)c.stick_migrations,
            (unsigned long long)c.work_steals,
            (unsigned long long)c.residency_lost_to_rebalance_bytes);
    }
    std::fprintf(f,
        "D2_MOE_LIVE SHARED_EXPERT_CALLS=%llu slice_layout_mismatch=%llu "
        "stick_retains=%llu stick_assigns=%llu\n"
        "D2_MOE_LIVE EXPERT_GPU_ACQUIRE=%llu EXPERT_GPU_EXEC=%llu "
        "HOST_GEMV_EXPERT=%llu\n"
        "D2_MOE_DECODE K2_MOE_LAYER_CALLS=%llu MOE_PLACE_CALLS=%llu "
        "EXPERTS_SELECTED=%llu EXPERTS_EXECUTED=%llu parity=%d\n",
        (unsigned long long)c.shared_expert_calls,
        (unsigned long long)c.expert_slice_layout_mismatch,
        (unsigned long long)c.expert_stick_retains,
        (unsigned long long)c.expert_stick_assigns,
        (unsigned long long)c.expert_gpu_acquire,
        (unsigned long long)c.expert_gpu_exec,
        (unsigned long long)c.host_gemv_expert,
        (unsigned long long)c.decode_moe_layer_calls,
        (unsigned long long)c.decode_moe_place_calls,
        (unsigned long long)c.decode_experts_selected,
        (unsigned long long)c.decode_experts_executed,
        (c.decode_experts_selected == c.decode_experts_executed) ? 1 : 0);
    EmitDualStickMechanics(f);
    std::fflush(f);
}

} // namespace Deep2
