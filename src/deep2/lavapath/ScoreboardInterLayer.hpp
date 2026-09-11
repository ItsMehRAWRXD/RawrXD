#pragma once
/* ScoreboardInterLayer — lightweight N→N+1 release (enqueue only). LIVE=0.
   COMPLETION=event producer; PUMP/Ensure=dispatch path. ≤99. */
#include "ScoreboardProductState.hpp"
#include "TensorScoreboard.hpp"
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

/* Publish only: CAS once, enqueue Io for N+1. No Ensure/dispatch here. */
inline int ReleaseNextLayerFromCompletion(TensorId completed) noexcept {
    InterLayerObs& o = InterLayer();
    o.nCompletionObs.fetch_add(1, std::memory_order_acq_rel);
    o.releaseAttempts.fetch_add(1, std::memory_order_acq_rel);
    if (completed >= 64u)
        return 0;
    uint32_t exp = 0;
    if (!o.releasedEpoch[completed].compare_exchange_strong(
            exp, 1u, std::memory_order_acq_rel, std::memory_order_acquire)) {
        o.releaseDupDropped.fetch_add(1, std::memory_order_acq_rel);
        return 0;
    }
    o.releaseWins.fetch_add(1, std::memory_order_acq_rel);
    const TensorId next = completed + 1u;
    TensorScore* t = ProductSb().sb.get(next);
    if (!t)
        return 0;
    const uint32_t st = t->state.load(std::memory_order_acquire);
    if (st == (uint32_t)ResidencyState::Absent) {
        if (!ProductSb().sb.enqueueIo(next))
            return 0;
    } else if (st != (uint32_t)ResidencyState::IoPending &&
               st != (uint32_t)ResidencyState::RamReady &&
               st != (uint32_t)ResidencyState::GpuPending &&
               st != (uint32_t)ResidencyState::GpuReady) {
        return 0;
    }
    o.nPlus1DepReleaseObs.fetch_add(1, std::memory_order_acq_rel);
    o.lastReleasedNext.store(next, std::memory_order_release);
    return 1;
}

inline void NoteSequentialNPlus1Issue(uint32_t layer) noexcept {
    if (layer > 0)
        InterLayer().sequentialNPlus1Issue.fetch_add(1, std::memory_order_acq_rel);
}

inline int NoteReadyExecFromScoreboardRelease(uint32_t layer) noexcept {
    if (InterLayer().lastReleasedNext.load(std::memory_order_acquire) != layer)
        return 0;
    InterLayer().nPlus1ReadyFromSbObs.fetch_add(1, std::memory_order_acq_rel);
    return 1;
}

inline int NoteSubmitFromScoreboardRelease(uint32_t layer) noexcept {
    if (InterLayer().lastReleasedNext.load(std::memory_order_acquire) != layer)
        return 0;
    InterLayer().nPlus1SubmitFromSbObs.fetch_add(1, std::memory_order_acq_rel);
    return 1;
}

/* Tip only — SEQUENTIAL_N_PLUS_1_ISSUE may still be >0. */
inline int InterLayerProgressOwnedTip() noexcept {
    InterLayerObs& o = InterLayer();
    return (o.nCompletionObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1DepReleaseObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1ReadyFromSbObs.load(std::memory_order_acquire) > 0 &&
            o.nPlus1SubmitFromSbObs.load(std::memory_order_acquire) > 0 &&
            o.releaseWins.load(std::memory_order_acquire) > 0)
               ? 1
               : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
