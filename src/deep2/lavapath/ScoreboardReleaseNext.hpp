#pragma once
#include "ScoreboardOwnershipBridge.hpp"
#include "ScoreboardOwnershipTypes.hpp"

namespace rawrxd::deep2 {

template<class Scoreboard>
bool ReleaseNextFromCompletion(
    Scoreboard& sb,
    const LayerEdge& e,
    std::atomic<uint32_t>& releasedGen) noexcept {

    OwnershipObs().completionN.fetch_add(1, std::memory_order_relaxed);
    uint32_t expected = releasedGen.load(std::memory_order_acquire);

    if (expected == e.from.generation) {
        OwnershipObs().releaseDupDrops.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (!releasedGen.compare_exchange_strong(
            expected, e.from.generation,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        OwnershipObs().releaseDupDrops.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (!sb.enqueueIo(e.to.layer, e.to.generation))
        return false;

    OwnershipObs().releaseWins.fetch_add(1, std::memory_order_relaxed);
    NoteReady();
    return true;
}

} // namespace rawrxd::deep2
