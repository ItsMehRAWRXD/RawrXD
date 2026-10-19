#pragma once
#include "ScoreboardOwnershipBridge.hpp"
#include "ScoreboardOwnershipTypes.hpp"

namespace rawrxd::deep2 {

template<class Scoreboard, class SubmitFn>
bool TryIssueNextFromScoreboard(
    Scoreboard& sb,
    SubmitFn&& submit) noexcept {

    OwnershipDecision d{};
    if (!sb.nextLayerRunnable(d))
        return false;
    if (!d.runnable || d.owner != IssueOwner::Scoreboard)
        return false;
    if (!submit(d.layer))
        return false;

    NoteSubmit();
    return true;
}

} // namespace rawrxd::deep2
