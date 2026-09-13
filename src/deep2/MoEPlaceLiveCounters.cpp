/* MoEPlaceLiveCounters.cpp — ≤99 lines. */
#include "MoEPlaceLiveCounters.hpp"
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
    const uint64_t tok = c.moe_tokens ? c.moe_tokens : 1ull;
    std::fprintf(f,
        "D2_MOE_LIVE moe_ffn_enter=%llu moe_place_enter=%llu "
        "ffn_dispatch_moe=%llu ffn_dispatch_dense=%llu ffn_dispatch_ssm=%llu\n"
        "D2_MOE_LIVE experts_selected=%llu experts_executed=%llu "
        "parity=%d thrash_tokens=%llu\n"
        "D2_MOE_LIVE hits=%llu misses=%llu miss_bytes=%llu "
        "EXPERT_MISS_BYTES_PER_TOKEN=%llu acquire_ok=%llu acquire_fail=%llu "
        "markhot=%llu\n",
        (unsigned long long)c.moe_ffn_enter,
        (unsigned long long)c.moe_place_enter,
        (unsigned long long)c.ffn_dispatch_moe,
        (unsigned long long)c.ffn_dispatch_dense,
        (unsigned long long)c.ffn_dispatch_ssm,
        (unsigned long long)c.experts_selected,
        (unsigned long long)c.experts_executed,
        (c.experts_selected == c.experts_executed) ? 1 : 0,
        (unsigned long long)c.moe_thrash_tokens,
        (unsigned long long)c.expert_cache_hits,
        (unsigned long long)c.expert_cache_misses,
        (unsigned long long)c.expert_miss_bytes,
        (unsigned long long)(c.expert_miss_bytes / tok),
        (unsigned long long)c.expert_acquire_ok,
        (unsigned long long)c.expert_acquire_fail,
        (unsigned long long)c.expert_markhot);
    std::fflush(f);
}

} // namespace Deep2
