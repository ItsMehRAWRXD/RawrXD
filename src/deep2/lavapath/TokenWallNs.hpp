#pragma once
/* TOKEN_WALL_NS authority; SECONDS/TPS display-only. ≤99. */
/* Deep2 = IndexedModel + LiveWorkingSet + FutureConsumerPrefetch + LaneIsolatedGPUExec + NanosecondStageTelemetry + TokenDeadline(6_666_667ns); */
#include <chrono>
#include <cstdint>
#include <cstdio>

#ifndef TOKEN_WALL_TARGET_NS
#define TOKEN_WALL_TARGET_NS 6666667ull /* 150 TPS */
#endif

namespace Deep2 {
namespace tokenwall {

inline uint64_t NowNs() {
    using clock = std::chrono::steady_clock;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            clock::now().time_since_epoch())
            .count());
}

inline uint64_t DeltaNs(uint64_t beginNs, uint64_t endNs) {
    return endNs > beginNs ? (endNs - beginNs) : 0ull;
}

/* Authoritative receipt; SECONDS/TPS derived for display only. */
inline void EmitCommitted(FILE* f, uint32_t tokenId, uint32_t decodeStep,
                          uint64_t tokenWallNs, uint32_t steady) {
    if (!f) return;
    const uint64_t target = TOKEN_WALL_TARGET_NS;
    const long long over =
        static_cast<long long>(tokenWallNs) - static_cast<long long>(target);
    const double seconds =
        static_cast<double>(tokenWallNs) / 1000000000.0;
    const double tps =
        tokenWallNs ? (1000000000.0 / static_cast<double>(tokenWallNs)) : 0.0;
    const int pass150 = (tokenWallNs > 0 && tokenWallNs <= target) ? 1 : 0;
    const long long margin = static_cast<long long>(target) - static_cast<long long>(tokenWallNs);
    /* ns → wall → INSTANT_TPS → 150TPS budget margin; OWNER=TOKEN_WALL stage. */
    fprintf(f,
            "TOKEN=%u DECODE_STEP=%u STEADY=%u TOKEN_WALL_NS=%llu "
            "TOKEN_WALL_MS=%.6f INSTANT_TPS=%.3f BUDGET_NS=%llu MARGIN_NS=%lld "
            "TARGET_NS=%llu OVER_TARGET_NS=%lld "
            "SECONDS_PER_TOKEN=%.9f TPS=%.6f PASS_150=%d "
            "NOTE=TOKEN_WALL_TELEMETRY_NOT_PROMOTE_GATE\n",
            tokenId, decodeStep, steady ? 1u : 0u,
            static_cast<unsigned long long>(tokenWallNs),
            tokenWallNs / 1e6, tps,
            static_cast<unsigned long long>(target), margin,
            static_cast<unsigned long long>(target), over, seconds, tps,
            pass150);
    fflush(f);
}

} /* namespace tokenwall */
} /* namespace Deep2 */
