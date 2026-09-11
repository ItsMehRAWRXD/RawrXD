#pragma once
/* ScoreboardGen — monotonic generation IDs (stale-completion safety). ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct ScoreboardGen {
    std::atomic<uint64_t> next{1};

    uint64_t mint() noexcept {
        return next.fetch_add(1, std::memory_order_acq_rel);
    }
};

inline ScoreboardGen& GlobalScoreboardGen() {
    static ScoreboardGen g;
    return g;
}

inline int GenerationMatches(uint64_t expected, uint64_t observed) noexcept {
    return expected != 0 && expected == observed ? 1 : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
