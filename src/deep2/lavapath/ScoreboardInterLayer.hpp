#pragma once
/* ScoreboardInterLayer — product interlayer obs only. LIVE=0. ≤99.
   ReleaseNext lives in ScoreboardReleaseNext.hpp (enqueue-only). */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct InterLayerObs {
    std::atomic<uint32_t> nCompletionObs{0};
    std::atomic<uint32_t> releaseAttempts{0};
    std::atomic<uint32_t> releaseWins{0};
    std::atomic<uint32_t> releaseDupDropped{0};
    std::atomic<uint32_t> nPlus1DepReleaseObs{0};
    std::atomic<uint32_t> nPlus1ReadyFromSbObs{0};
    std::atomic<uint32_t> nPlus1SubmitFromSbObs{0};
    std::atomic<uint32_t> lastReleasedNext{0xffffffffu};
    std::atomic<uint32_t> releasedEpoch[64];
    std::atomic<uint32_t> sequentialNPlus1Issue{0};

    void reset() noexcept {
        nCompletionObs.store(0, std::memory_order_relaxed);
        releaseAttempts.store(0, std::memory_order_relaxed);
        releaseWins.store(0, std::memory_order_relaxed);
        releaseDupDropped.store(0, std::memory_order_relaxed);
        nPlus1DepReleaseObs.store(0, std::memory_order_relaxed);
        nPlus1ReadyFromSbObs.store(0, std::memory_order_relaxed);
        nPlus1SubmitFromSbObs.store(0, std::memory_order_relaxed);
        lastReleasedNext.store(0xffffffffu, std::memory_order_relaxed);
        sequentialNPlus1Issue.store(0, std::memory_order_relaxed);
        for (uint32_t i = 0; i < 64u; ++i)
            releasedEpoch[i].store(0, std::memory_order_relaxed);
    }
};

inline InterLayerObs& InterLayer() noexcept {
    static InterLayerObs o;
    return o;
}

/* Dep-release tip only — does not require scoreboardIssue. */
inline int InterLayerDepProgressOwnedTip() noexcept {
    InterLayerObs& o = InterLayer();
    return (o.nCompletionObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1DepReleaseObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1ReadyFromSbObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1SubmitFromSbObs.load(std::memory_order_acquire) > 0 &&
            o.releaseWins.load(std::memory_order_acquire) > 0)
               ? 1
               : 0;
}

/* Clear release CAS slots for a new outer layer walk (totals kept). */
inline void BeginInterLayerWalk() noexcept {
    InterLayerObs& o = InterLayer();
    o.lastReleasedNext.store(0xffffffffu, std::memory_order_relaxed);
    for (uint32_t i = 0; i < 64u; ++i)
        o.releasedEpoch[i].store(0, std::memory_order_relaxed);
}

} /* namespace scoreboard */
} /* namespace Deep2 */
