#pragma once
/* ScoreboardTransition — legal residency transition checks. ≤99. */
#include "ScoreboardTypes.hpp"

namespace Deep2 {
namespace scoreboard {

inline int LegalTransition(ResidencyState from, ResidencyState to) noexcept {
    switch (from) {
    case ResidencyState::Absent:
        return to == ResidencyState::IoPending ? 1 : 0;
    case ResidencyState::IoPending:
        return to == ResidencyState::RamReady ? 1 : 0;
    case ResidencyState::RamReady:
        return to == ResidencyState::GpuPending || to == ResidencyState::Retired
                   ? 1
                   : 0;
    case ResidencyState::GpuPending:
        return to == ResidencyState::GpuReady ? 1 : 0;
    case ResidencyState::GpuReady:
        return to == ResidencyState::Executing || to == ResidencyState::Retired
                   ? 1
                   : 0;
    case ResidencyState::Executing:
        return to == ResidencyState::Retired || to == ResidencyState::GpuReady
                   ? 1
                   : 0;
    case ResidencyState::Retired:
        return 0;
    default:
        return 0;
    }
}

} /* namespace scoreboard */
} /* namespace Deep2 */
