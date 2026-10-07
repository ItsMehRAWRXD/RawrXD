#pragma once
#include "../rawr_destructive_action_guard.hpp"
#include <cstdlib>
#include <string>
namespace rawr {
inline int ToolGitStatus(const SafetyPolicy& p, const std::string& ws) {
    if (!p.mayRead()) return -1;
    std::string cmd = "git -C \"" + ws + "\" status --short";
    return std::system(cmd.c_str());
}
inline int ToolGitPushBlocked(const SafetyPolicy& p) {
    if (DestructiveBlocked(p, "git push")) return -9;
    return 0;
}
} // namespace rawr
