// rawr_safety_policy.hpp — autonomy + hard blocks
#pragma once
#include <cstring>
#include <cctype>
#include <string>

namespace rawr {

enum class AutonomyLevel : int {
    Off = 0,
    Read = 1,
    Patch = 2,
    Build = 3,
    Full = 4
};

inline AutonomyLevel ParseAutonomy(const char* s) {
    if (!s) return AutonomyLevel::Off;
    if (!_stricmp(s, "read")) return AutonomyLevel::Read;
    if (!_stricmp(s, "patch")) return AutonomyLevel::Patch;
    if (!_stricmp(s, "build")) return AutonomyLevel::Build;
    if (!_stricmp(s, "full")) return AutonomyLevel::Full;
    return AutonomyLevel::Off;
}

inline const char* AutonomyName(AutonomyLevel a) {
    switch (a) {
    case AutonomyLevel::Read: return "read";
    case AutonomyLevel::Patch: return "patch";
    case AutonomyLevel::Build: return "build";
    case AutonomyLevel::Full: return "full";
    default: return "off";
    }
}

struct SafetyPolicy {
    AutonomyLevel level = AutonomyLevel::Off;
    bool allowNetwork = false;
    bool allowGitPush = false;
    bool allowDelete = false;
    bool userApprovedGitPush = false;

    bool mayRead() const { return (int)level >= (int)AutonomyLevel::Read; }
    bool mayPatch() const { return (int)level >= (int)AutonomyLevel::Patch; }
    bool mayBuild() const { return (int)level >= (int)AutonomyLevel::Build; }

    bool blockNetwork() const { return !allowNetwork; }
    bool blockGitPush() const { return !allowGitPush && !userApprovedGitPush; }
    bool blockDelete() const { return !allowDelete; }

    bool isDestructive(const std::string& action) const {
        return action.find("git push") != std::string::npos ||
               action.find("rm -rf") != std::string::npos ||
               action.find("Wipe") != std::string::npos ||
               action.find("delete repo") != std::string::npos;
    }
};

inline bool PathInsideWorkspace(const std::string& workspace,
                                const std::string& path) {
    if (workspace.empty() || path.empty()) return false;
    // Simple prefix guard (case-insensitive on Windows).
    if (path.size() < workspace.size()) return false;
#ifdef _WIN32
    for (size_t i = 0; i < workspace.size(); ++i) {
        char a = (char)tolower((unsigned char)workspace[i]);
        char b = (char)tolower((unsigned char)path[i]);
        if (a == '/') a = '\\';
        if (b == '/') b = '\\';
        if (a != b) return false;
    }
    return true;
#else
    return path.compare(0, workspace.size(), workspace) == 0;
#endif
}

} // namespace rawr
