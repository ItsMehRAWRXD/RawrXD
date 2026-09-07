#pragma once
#include "rawr_context_window.hpp"
namespace rawr {
inline void CompactHistory(SessionState& s) { TrimHistory(s, 24); }
} // namespace rawr
