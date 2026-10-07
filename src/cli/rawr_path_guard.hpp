#pragma once
#include "rawr_safety_policy.hpp"
namespace rawr {
inline bool PathGuardOk(const std::string& workspace, const std::string& path) {
    return PathInsideWorkspace(workspace, path);
}
} // namespace rawr
