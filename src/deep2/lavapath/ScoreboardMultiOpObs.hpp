#pragma once
/* ScoreboardMultiOpObs — distinct-layer multi-op counters. LIVE=0. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct ScoreboardMultiOpObs {
    std::atomic<uint64_t> distinctLayerBits{0};
    std::atomic<uint32_t> distinctLayers{0};
    std::atomic<uint32_t> lastLayer{0xffffffffu};

    void reset() noexcept {
        distinctLayerBits.store(0, std::memory_order_relaxed);
        distinctLayers.store(0, std::memory_order_relaxed);
        lastLayer.store(0xffffffffu, std::memory_order_relaxed);
    }

    void note(uint32_t layer) noexcept {
        lastLayer.store(layer, std::memory_order_release);
        if (layer >= 64u)
            return;
        const uint64_t bit = 1ull << layer;
        const uint64_t prev =
            distinctLayerBits.fetch_or(bit, std::memory_order_acq_rel);
        if ((prev & bit) == 0ull)
            distinctLayers.fetch_add(1, std::memory_order_acq_rel);
    }
};

inline ScoreboardMultiOpObs& MultiOpObs() {
    static ScoreboardMultiOpObs o;
    return o;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
