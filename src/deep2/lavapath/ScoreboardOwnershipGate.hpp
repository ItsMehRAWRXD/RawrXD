#pragma once
#include "ScoreboardOwnershipBridge.hpp"

namespace rawrxd::deep2 {

struct ScoreboardOwnershipGate {
    uint32_t completionN=0, releaseWins=0, releaseDupDrops=0;
    uint32_t nPlus1Ready=0, nPlus1Submit=0;
    uint32_t sequentialIssue=0, scoreboardIssue=0;

    bool interLayerOwned() const noexcept {
        return InterLayerProgressOwnedTip();
    }

    bool schedulerOwnershipEligible() const noexcept {
        return interLayerOwned() && sequentialIssue == 0;
    }
};

inline ScoreboardOwnershipGate ReadOwnershipGate() noexcept {
    auto& o = OwnershipObs();
    ScoreboardOwnershipGate g{};
    g.completionN=o.completionN.load();
    g.releaseWins=o.releaseWins.load();
    g.releaseDupDrops=o.releaseDupDrops.load();
    g.nPlus1Ready=o.nPlus1Ready.load();
    g.nPlus1Submit=o.nPlus1Submit.load();
    g.sequentialIssue=o.sequentialIssue.load();
    g.scoreboardIssue=o.scoreboardIssue.load();
    return g;
}

} // namespace rawrxd::deep2
