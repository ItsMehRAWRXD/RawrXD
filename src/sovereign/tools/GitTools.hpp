// ============================================================================
// GitTools.hpp - Git Integration Tools for Agent
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace Sovereign {

// Git status
struct GitStatus {
    std::string branch;
    std::vector<std::string> staged;
    std::vector<std::string> unstaged;
    std::vector<std::string> untracked;
    int ahead;
    int behind;
    bool hasConflicts;
};

// Git commit
struct GitCommit {
    std::string hash;
    std::string author;
    std::string message;
    uint64_t timestamp;
    std::vector<std::string> parents;
};

// Git diff
struct GitDiff {
    std::string file;
    std::string oldContent;
    std::string newContent;
    int additions;
    int deletions;
};

// Git tools
class GitTools {
public:
    GitTools(const std::string& repoPath);
    ~GitTools();

    // Status
    GitStatus GetStatus();
    std::string GetBranch();
    std::string GetCurrentHash();

    // Diff
    GitDiff GetDiff(const std::string& file);
    std::vector<GitDiff> GetAllDiffs();
    std::string GetUnifiedDiff(const std::string& file);

    // Log
    std::vector<GitCommit> GetLog(int count = 10);
    GitCommit GetCommit(const std::string& hash);

    // Operations
    bool Stage(const std::string& file);
    bool Unstage(const std::string& file);
    bool Commit(const std::string& message);
    bool Push(const std::string& remote = "origin", const std::string& branch = "");
    bool Pull(const std::string& remote = "origin", const std::string& branch = "");
    bool Checkout(const std::string& branch);
    bool CreateBranch(const std::string& name);
    bool Merge(const std::string& branch);
    bool Revert(const std::string& hash);
    bool Reset(const std::string& target, bool hard = false);

    // Stash
    bool Stash(const std::string& message = "");
    bool StashPop();
    std::vector<std::string> ListStash();

    // Blame
    std::vector<std::pair<std::string, int>> Blame(const std::string& file);

    // Config
    void SetAuthor(const std::string& name, const std::string& email);

    // Utility
    bool IsRepo();
    std::string GetRootPath();
    bool HasUncommittedChanges();

private:
    std::string repoPath_;
    
    std::string ExecGit(const std::vector<std::string>& args);
    std::vector<std::string> ExecGitLines(const std::vector<std::string>& args);
};

} // namespace Sovereign
