#pragma once
#include "../rawr_command_guard.hpp"
#include <cstdlib>
#include <string>
namespace rawr {
inline int ToolRunProcess(const SafetyPolicy& p, const std::string& cmd) {
    if (!CommandGuardOk(p, cmd)) return -2;
    if ((int)p.level < (int)AutonomyLevel::Build) return -1;
    return std::system(cmd.c_str());
}
} // namespace rawr
