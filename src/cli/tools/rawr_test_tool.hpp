#pragma once
#include "rawr_build_tool.hpp"
namespace rawr {
inline int ToolRunTest(const SafetyPolicy& p, const std::string& cmd) {
    return ToolRunBuild(p, cmd);
}
} // namespace rawr
