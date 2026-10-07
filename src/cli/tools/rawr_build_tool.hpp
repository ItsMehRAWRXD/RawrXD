#pragma once
#include "../rawr_command_guard.hpp"
#include <cstdlib>
#include <string>
namespace rawr {
inline int ToolRunBuild(const SafetyPolicy& p, const std::string& cmd) {
    if (!p.mayBuild()) return -1;
    if (!CommandGuardOk(p, cmd)) return -2;
    return std::system(cmd.c_str());
}
} // namespace rawr
