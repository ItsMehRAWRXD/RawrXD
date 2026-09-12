#pragma once
/* ScoreboardJoinDemote — await/reclaim only; no pump. LIVE=0. ≤99.
   Pump from fence tips is hidden progress authority — forbidden. */
#include "ScoreboardFenceObs.hpp"
#include <cstdint>
#include <thread>

namespace Deep2 {
namespace scoreboard {

template <typename GateT>
inline int TryReadyAwaitTip(GateT& gate) noexcept {
    if (gate.ready.load(std::memory_order_acquire)) {
        FenceObs().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    FenceObs().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

template <typename SlotT>
inline int TryWorkerDoneAwaitTip(SlotT& s) noexcept {
    if (!s.worker.joinable()) {
        FenceObs().workerSkipObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (s.gate.ready.load(std::memory_order_acquire) ||
        s.gate.failed.load(std::memory_order_acquire)) {
        s.worker.join();
        FenceObs().workerDoneJoinObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    FenceObs().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

/* Fence3 reclaim-only: acquire(done)→join. No pump. */
inline int TryOutPrefetchDoneTip(std::thread& th,
                                 std::atomic<uint32_t>& done) noexcept {
    ScoreboardFenceObs& f = FenceObs();
    f.fence3Attempts.fetch_add(1, std::memory_order_acq_rel);
    if (!th.joinable()) {
        f.fence3Demoted.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (done.load(std::memory_order_acquire)) {
        th.join();
        f.fence3Demoted.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    f.fence3FallbackJoin.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
