#pragma once
#include "../rawr_path_guard.hpp"
#include "../rawr_patch_engine.hpp"
#include <string>
namespace rawr {
inline bool ToolReadFile(const SafetyPolicy& p, const std::string& ws,
                         const std::string& path, std::string& out) {
    if (!p.mayRead()) return false;
    if (!PathGuardOk(ws, path)) return false;
    out = PatchEngine::ReadAll(path);
    return true;
}
} // namespace rawr
