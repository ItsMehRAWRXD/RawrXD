//=============================================================================
// RawrXD Git Helper
// Lightweight git integration for status bar - zero dependencies
//=============================================================================
#pragma once

#include <string>
#include <array>
#include <memory>

namespace RawrXD {
namespace Utils {

class GitHelper {
public:
    // Get current branch name (e.g., "main", "feature/my-branch")
    // Returns "master" if not in a git repo or git not available
    static std::string GetCurrentBranch();
    
    // Get short commit hash (e.g., "a1b2c3d")
    static std::string GetShortCommitHash();
    
    // Check if current directory is a git repository
    static bool IsGitRepository();
    
    // Get repository root path
    static std::string GetRepositoryRoot();
    
    // Check if working tree is dirty (has uncommitted changes)
    static bool IsWorkingTreeDirty();
    
    // Get ahead/behind count from remote (e.g., "+2-1" means 2 ahead, 1 behind)
    static std::string GetRemoteStatus();

private:
    // Execute git command and return output
    static std::string ExecuteGitCommand(const char* args);
    
    // Trim whitespace and newlines from string
    static std::string Trim(const std::string& str);
};

} // namespace Utils
} // namespace RawrXD
