#pragma once
#include "rawr_safety_policy.hpp"
namespace rawr {
inline bool NetworkGuardBlocks(const SafetyPolicy& p) { return p.blockNetwork(); }
} // namespace rawr
