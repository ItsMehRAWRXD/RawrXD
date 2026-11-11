#pragma once
/* ScoreboardIssuance — issuance tracking. LIVE=0. ≤99. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct IssuanceState {
    void reset() noexcept {}
};

inline IssuanceState& Issuance() noexcept {
    static IssuanceState s;
    return s;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
