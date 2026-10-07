#pragma once
#include "rawr_session_state.hpp"
#include <cstddef>
namespace rawr {
inline void TrimHistory(SessionState& s, size_t maxTurns = 32) {
    if (s.history.size() <= maxTurns) return;
    s.history.erase(s.history.begin(),
                    s.history.begin() + (s.history.size() - maxTurns));
}
} // namespace rawr
