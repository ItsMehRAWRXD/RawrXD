#pragma once
#include "rawr_safety_policy.hpp"
#include <string>
namespace rawr {
inline bool PermissionAllow(const SafetyPolicy& p, const std::string& action) {
    if (p.isDestructive(action) && p.blockDelete()) return false;
    if (action.find("git push") != std::string::npos && p.blockGitPush())
        return false;
    if (action.find("http") != std::string::npos && p.blockNetwork())
        return false;
    return true;
}
} // namespace rawr
