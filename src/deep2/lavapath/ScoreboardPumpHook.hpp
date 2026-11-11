#pragma once
/* ScoreboardPumpHook — pump issue hook. LIVE=0. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

using PumpIssueFnT = int (*)();

inline PumpIssueFnT PumpIssueHook() noexcept {
    return nullptr;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
