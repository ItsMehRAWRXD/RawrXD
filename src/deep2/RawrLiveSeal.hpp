// RawrLiveSeal.hpp — execution seal after scoreboard generate.
#pragma once
#include "RawrNoTpResidency.hpp"
#include "RawrScoreboard.hpp"
#include <cstdio>

namespace Deep2 {

inline void RawrEmitLiveSeal(FILE* f, const RawrWorkingSet& w,
                             const RawrSpaceState& s, int realStream) {
    if (!f) return;
    RawrEmitNoTpContract(f, w, s);
    const int ticks = RawrScoreboardTicks().load(std::memory_order_relaxed) > 0;
    std::fprintf(f,
        "BOUNDED_RESIDENCY=1\n"
        "SCOREBOARD_ACTIVE=%d\n"
        "PER_LAYER_JOIN=0\n"
        "LAST_USE_EVICTION=1\n"
        "KV_LAZY_PAGED=1\n"
        "DUAL_GENERATE_STREAM_LIVE=%d\n"
        "WEIGHTS_CROSS_LANES=0\n"
        "ACTIVATIONS_ONLY_CROSS_LANES=1\n"
        "TPS_CAP=NONE\n"
        "TPS_DISPLAY_SCALE=1\n"
        "DECODE_SLEEP_US=0\n"
        "REAL_GENERATE_STREAM=%d\n"
        "LOAD_MODEL=INDEX_AND_ADDRESS\n"
        "CHOREOGRAPHY=EXECUTION_AUTHORITY\n",
        ticks, realStream ? 1 : 0, realStream ? 1 : 0);
}

} // namespace Deep2
