// ============================================================================
// SourceControlPanel.hpp - Source Control Panel for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct SCMChange {
    std::string file;
    std::string status; // M, A, D, R, C, U, ? 
    std::string oldPath;
    uint64_t size;
    std::string diffPreview;
};

struct SCMCommit {
    std::string hash;
    std::string author;
    std::string message;
    uint64_t timestamp;
    std::vector<std::string> files;
};

struct SCMBranch {
    std::string name;
    bool isCurrent;
    bool isRemote;
    std::string upstream;
    int ahead;
    int behind;
    std::string lastCommit;
};

class SourceControlPanel {
public:
    SourceControlPanel();
    ~SourceControlPanel();

    bool Initialize(const std::string& repoPath);
    void Shutdown();

    std::vector<SCMChange> GetChanges();
    std::vector<SCMChange> GetStagedChanges();
    std::vector<SCMCommit> GetLog(int count = 20);
    std::vector<SCMBranch> GetBranches();

    bool Stage(const std::string& file);
    bool Unstage(const std::string& file);
    bool StageAll();
    bool Commit(const std::string& message);
    bool Push(const std::string& remote = "origin", const std::string& branch = "");
    bool Pull(const std::string& remote = "origin", const std::string& branch = "");
    bool Checkout(const std::string& branch);
    bool CreateBranch(const std::string& name);
    bool Merge(const std::string& branch);
    bool Discard(const std::string& file);

    std::string GetDiff(const std::string& file);
    std::string GetCurrentBranch();
    bool HasUncommittedChanges();
    bool IsRepository();

    void SetChangeCallback(std::function<void(const std::vector<SCMChange>&)> callback);

    struct SCMStats {
        uint64_t totalCommits;
        uint64_t totalBranches;
        uint64_t totalChanges;
        uint64_t operations;
    };
    SCMStats GetStats() const { return stats_; }

private:
    std::string repoPath_;
    SCMStats stats_;
    std::function<void(const std::vector<SCMChange>&)> changeCallback_;
    mutable std::mutex mutex_;
    
    std::string ExecGit(const std::vector<std::string>& args) const;
};

} // namespace Sovereign
