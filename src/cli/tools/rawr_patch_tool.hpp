#pragma once
#include "../rawr_path_guard.hpp"
#include "../rawr_patch_engine.hpp"
#include "../rawr_diff.hpp"
#include <string>
namespace rawr {
inline bool ToolApplyPatch(SafetyPolicy& p, PatchEngine& eng,
                           const std::string& ws, const std::string& path,
                           const std::string& newText, PatchRecord& out) {
    if (!p.mayPatch()) return false;
    if (!PathGuardOk(ws, path)) return false;
    std::string before = PatchEngine::ReadAll(path);
    out.diff = ShowDiff(before, newText);
    return eng.ApplyReplace(path, newText, out);
}
inline bool ToolUndoPatch(PatchEngine& eng, std::string& path) {
    return eng.UndoLast(path);
}
} // namespace rawr
