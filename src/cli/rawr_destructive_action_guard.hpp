#pragma once
#include "rawr_safety_policy.hpp"
#include <string>
namespace rawr {
inline bool DestructiveBlocked(const SafetyPolicy& p, const std::string& a) {
    return p.isDestructive(a) && (p.blockDelete() || p.blockGitPush());
}
} // namespace rawr
