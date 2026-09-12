#pragma once
/* ScoreboardFenceObs — leaf telemetry only. No Bind/Seal. ≤99. */
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct ScoreboardFenceObs {
    std::atomic<uint32_t> readySkipObs{0};
    std::atomic<uint32_t> pumpContinueObs{0};
    std::atomic<uint32_t> fallbackJoinObs{0};
    std::atomic<uint32_t> workerDoneJoinObs{0};
    std::atomic<uint32_t> workerSkipObs{0};
    std::atomic<uint32_t> fence3Attempts{0};
    std::atomic<uint32_t> fence3Demoted{0};
    std::atomic<uint32_t> fence3FallbackJoin{0};
    std::atomic<uint32_t> fence3PumpWork{0};
    std::atomic<uint32_t> joinAllAttempts{0};
    std::atomic<uint32_t> joinAllDemoted{0};
    std::atomic<uint32_t> joinAllFallback{0};

    void reset() noexcept {
        readySkipObs.store(0, std::memory_order_relaxed);
        pumpContinueObs.store(0, std::memory_order_relaxed);
        fallbackJoinObs.store(0, std::memory_order_relaxed);
        workerDoneJoinObs.store(0, std::memory_order_relaxed);
        workerSkipObs.store(0, std::memory_order_relaxed);
        fence3Attempts.store(0, std::memory_order_relaxed);
        fence3Demoted.store(0, std::memory_order_relaxed);
        fence3FallbackJoin.store(0, std::memory_order_relaxed);
        fence3PumpWork.store(0, std::memory_order_relaxed);
        joinAllAttempts.store(0, std::memory_order_relaxed);
        joinAllDemoted.store(0, std::memory_order_relaxed);
        joinAllFallback.store(0, std::memory_order_relaxed);
    }
};

inline ScoreboardFenceObs& FenceObs() noexcept {
    static ScoreboardFenceObs o;
    return o;
}

inline ScoreboardFenceObs& JoinDemote() noexcept { return FenceObs(); }

} /* namespace scoreboard */
} /* namespace Deep2 */
