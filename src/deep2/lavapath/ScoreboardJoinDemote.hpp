#pragma once
/* ScoreboardJoinDemote — ForwardMLALayers wait tips. LIVE=0. ≤99. */
#include "ProductScoreboardBind.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct JoinDemoteHooks {
    std::atomic<uint32_t> readySkipObs{0};
    std::atomic<uint32_t> pumpContinueObs{0};
    std::atomic<uint32_t> fallbackJoinObs{0};
    std::atomic<uint32_t> workerDoneJoinObs{0};
    std::atomic<uint32_t> workerSkipObs{0};
};

inline JoinDemoteHooks& JoinDemote() {
    static JoinDemoteHooks h;
    return h;
}

/* Fence1: pre-RunMla ready-await. 1=skip join. */
template <typename GateT>
inline int TryReadyAwaitTip(GateT& gate) noexcept {
    if (gate.ready.load(std::memory_order_acquire)) {
        JoinDemote().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        (void)ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        JoinDemote().pumpContinueObs.fetch_add(1, std::memory_order_acq_rel);
        if (gate.ready.load(std::memory_order_acquire)) {
            JoinDemote().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
            return 1;
        }
    }
    JoinDemote().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

/* Fence2: issueLayer slot-reuse. 1=handled (skip or done-join). 0=block. */
template <typename SlotT>
inline int TryWorkerDoneAwaitTip(SlotT& s) noexcept {
    if (!s.worker.joinable()) {
        JoinDemote().workerSkipObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (s.gate.ready.load(std::memory_order_acquire) ||
        s.gate.failed.load(std::memory_order_acquire)) {
        s.worker.join();
        JoinDemote().workerDoneJoinObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        (void)ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        JoinDemote().pumpContinueObs.fetch_add(1, std::memory_order_acq_rel);
        if (s.gate.ready.load(std::memory_order_acquire) ||
            s.gate.failed.load(std::memory_order_acquire)) {
            s.worker.join();
            JoinDemote().workerDoneJoinObs.fetch_add(1,
                                                     std::memory_order_acq_rel);
            return 1;
        }
    }
    JoinDemote().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
