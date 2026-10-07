#pragma once
#include "rawr_patch_engine.hpp"
#include <string>
namespace rawr {
inline std::string SnapshotFile(const std::string& path) {
    return PatchEngine::ReadAll(path);
}
} // namespace rawr
