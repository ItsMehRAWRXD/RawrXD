/* MoEPlaceLiveCounters.cpp — ≤99 lines. */
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
            "EXPERT_MISS_BYTES_PER_TOKEN=N/A_NOT_REACHED "
            "acquire_ok=%llu acquire_fail=%llu markhot=%llu\n",
            (unsigned long long)c.expert_acquire_ok,
            (unsigned long long)c.expert_acquire_fail,
            (unsigned long long)c.expert_markhot);
    } else {
        const uint64_t tok = c.moe_tokens ? c.moe_tokens : 1ull;
        std::fprintf(f,
            "D2_MOE_LIVE hits=%llu misses=%llu miss_bytes=%llu "
            "EXPERT_MISS_BYTES_PER_TOKEN=%llu acquire_ok=%llu "
            "acquire_fail=%llu markhot=%llu\n",
            (unsigned long long)c.expert_cache_hits,
            (unsigned long long)c.expert_cache_misses,
            (unsigned long long)c.expert_miss_bytes,
            (unsigned long long)(c.expert_miss_bytes / tok),
            (unsigned long long)c.expert_acquire_ok,
            (unsigned long long)c.expert_acquire_fail,
            (unsigned long long)c.expert_markhot);
    }
    std::fprintf(f,
        "D2_MOE_LIVE SHARED_EXPERT_CALLS=%llu slice_layout_mismatch=%llu "
        "stick_retains=%llu stick_assigns=%llu\n"
        "D2_MOE_DECODE K2_MOE_LAYER_CALLS=%llu MOE_PLACE_CALLS=%llu "
        "EXPERTS_SELECTED=%llu EXPERTS_EXECUTED=%llu parity=%d\n",
        (unsigned long long)c.shared_expert_calls,
        (unsigned long long)c.expert_slice_layout_mismatch,
        (unsigned long long)c.expert_stick_retains,
        (unsigned long long)c.expert_stick_assigns,
        (unsigned long long)c.decode_moe_layer_calls,
        (unsigned long long)c.decode_moe_place_calls,
        (unsigned long long)c.decode_experts_selected,
        (unsigned long long)c.decode_experts_executed,
        (c.decode_experts_selected == c.decode_experts_executed) ? 1 : 0);
    /* Product rawr path: emit DualStick runtime stick work (parity cert only
     * did this before — needed for BOTH_STICKS_EXECUTE conjunction). */
    EmitDualStickMechanics(f);
    std::fflush(f);
}

} // namespace Deep2
