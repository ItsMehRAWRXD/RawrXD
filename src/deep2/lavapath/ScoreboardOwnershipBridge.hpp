#pragma once
#include "ScoreboardOwnershipObs.hpp"

namespace rawrxd::deep2 {

inline void NoteReady() noexcept {
    OwnershipObs().nPlus1Ready.fetch_add(1, std::memory_order_relaxed);
}

inline void NoteSubmit() noexcept {
    OwnershipObs().scoreboardIssue.fetch_add(1, std::memory_order_relaxed);
    OwnershipObs().nPlus1Submit.fetch_add(1, std::memory_order_relaxed);
}

inline bool InterLayerProgressOwnedTip() noexcept {
    const auto& o = OwnershipObs();
    return o.releaseWins.load(std::memory_order_acquire) > 0 &&
           o.nPlus1Ready.load(std::memory_order_acquire) > 0 &&
           o.nPlus1Submit.load(std::memory_order_acquire) > 0 &&
           o.scoreboardIssue.load(std::memory_order_acquire) > 0;
}

} // namespace rawrxd::deep2
