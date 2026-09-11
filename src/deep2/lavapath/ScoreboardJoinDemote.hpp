#pragma once
/* ScoreboardJoinDemote — wait tips; FenceObs telemetry only. LIVE=0. ≤99. */
#include "ScoreboardFenceObs.hpp"
#include "ScoreboardProductState.hpp"
#include "ProductScoreboardWitness.hpp"
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
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        (void)ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        FenceObs().pumpContinueObs.fetch_add(1, std::memory_order_acq_rel);
        if (gate.ready.load(std::memory_order_acquire)) {
            FenceObs().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
            return 1;
        }
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
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        (void)ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        FenceObs().pumpContinueObs.fetch_add(1, std::memory_order_acq_rel);
        if (s.gate.ready.load(std::memory_order_acquire) ||
            s.gate.failed.load(std::memory_order_acquire)) {
            s.worker.join();
            FenceObs().workerDoneJoinObs.fetch_add(1, std::memory_order_acq_rel);
            return 1;
        }
    }
    FenceObs().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

/* Fence3: JOIN=reclaim only after acquire(done). Else fallback join. */
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
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        const int n = ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        if (n > 0)
            f.fence3PumpWork.fetch_add((uint32_t)n, std::memory_order_acq_rel);
        if (done.load(std::memory_order_acquire)) {
            th.join();
            f.fence3Demoted.fetch_add(1, std::memory_order_acq_rel);
            return 1;
        }
    }
    f.fence3FallbackJoin.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
