// ============================================================================
// GitIntegration.h - Production Git SCM Integration
// ============================================================================
// Features: Diff viewer, blame annotations, commit UI, status monitoring
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <chrono>

namespace RawrXD {
namespace SCM {

// Git file status
enum class FileStatus {
    Unmodified,
    Modified,
    Added,
    Deleted,
    Renamed,
    Copied,
    Untracked,
    Ignored,
    Conflict
};

// Line change type for diff
enum class LineChangeType {
    Unchanged,
    Added,
    Deleted,
    Modified
};

// Blame information for a line
struct BlameInfo {
    std::string commitHash;
    std::string author;
    std::string email;
    std::chrono::system_clock::time_point timestamp;
    std::string summary;
    int originalLine = 0;
    bool isBoundary = false;
};

// Diff hunk
struct DiffHunk {
    int oldStart = 0;
    int oldCount = 0;
    int newStart = 0;
    int newCount = 0;
    std::string header;
    std::vector<std::pair<LineChangeType, std::string>> lines;
};

// File diff
struct FileDiff {
    std::string oldPath;
    std::string newPath;
    FileStatus status;
    std::vector<DiffHunk> hunks;
    int additions = 0;
    int deletions = 0;
    bool isBinary = false;
};

// Commit information
struct CommitInfo {
    std::string hash;
    std::string shortHash;
    std::string author;
    std::string email;
    std::chrono::system_clock::time_point timestamp;
    std::string summary;
    std::string body;
    std::vector<std::string> parentHashes;
    int changedFiles = 0;
    int insertions = 0;
    int deletions = 0;
};

// Branch information
struct BranchInfo {
    std::string name;
    std::string remote;
    std::string upstream;
    bool isCurrent = false;
    int ahead = 0;
    int behind = 0;
};

// Repository status
struct RepoStatus {
    std::string branch;
    std::string upstream;
    int ahead = 0;
    int behind = 0;
    bool isMerging = false;
    bool isRebasing = false;
    std::string mergeHead;
    std::unordered_map<std::string, FileStatus> stagedFiles;
    std::unordered_map<std::string, FileStatus> unstagedFiles;
    std::vector<std::string> untrackedFiles;
    std::vector<std::string> conflictedFiles;
};

// Stash entry
struct StashEntry {
    int index = 0;
    std::string message;
    std::string commitHash;
};

// ============================================================================
// GitIntegration - Production Git Client
// ============================================================================

class GitIntegration {
public:
    GitIntegration();
    ~GitIntegration();

    // Initialize with repository path
    bool Initialize(const std::string& repoPath);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Repository info
    bool IsRepo() const;
    std::string GetRepoRoot() const;
    std::string GetGitDir() const;

    // Status
    RepoStatus GetStatus();
    FileStatus GetFileStatus(const std::string& path);
    bool IsFileTracked(const std::string& path);

    // Diff
    FileDiff GetFileDiff(const std::string& path, bool staged = false);
    std::vector<FileDiff> GetWorkingDiff();
    std::vector<FileDiff> GetStagedDiff();
    FileDiff GetCommitDiff(const std::string& commitHash);
    FileDiff GetCommitDiff(const std::string& oldCommit, const std::string& newCommit);

    // Blame
    std::vector<BlameInfo> GetBlame(const std::string& path, int startLine = 0, int lineCount = -1);
    BlameInfo GetBlameForLine(const std::string& path, int line);

    // Log
    std::vector<CommitInfo> GetLog(int maxCount = 50, const std::string& branch = "");
    CommitInfo GetCommit(const std::string& hash);
    std::vector<CommitInfo> GetLogForFile(const std::string& path, int maxCount = 50);

    // Branches
    std::vector<BranchInfo> GetBranches(bool includeRemote = false);
    BranchInfo GetCurrentBranch();
    bool CheckoutBranch(const std::string& branchName, bool create = false);
    bool DeleteBranch(const std::string& branchName, bool force = false);
    bool MergeBranch(const std::string& branchName);
    bool RebaseBranch(const std::string& branchName);

    // Staging
    bool StageFile(const std::string& path);
    bool StageFiles(const std::vector<std::string>& paths);
    bool StageAll();
    bool UnstageFile(const std::string& path);
    bool UnstageFiles(const std::vector<std::string>& paths);
    bool UnstageAll();

    // Commit
    bool Commit(const std::string& message);
    bool Commit(const std::string& message, const std::vector<std::string>& paths);
    bool AmendCommit(const std::string& message = "");

    // Discard
    bool DiscardFile(const std::string& path);
    bool DiscardFiles(const std::vector<std::string>& paths);
    bool DiscardAll();

    // Stash
    bool Stash(const std::string& message = "");
    bool StashPop(int index = 0);
    bool StashApply(int index = 0);
    bool StashDrop(int index = 0);
    std::vector<StashEntry> GetStashList();

    // Remote operations
    bool Fetch(const std::string& remote = "");
    bool Pull(const std::string& remote = "", const std::string& branch = "");
    bool Push(const std::string& remote = "", const std::string& branch = "");

    // Tags
    std::vector<std::string> GetTags();
    bool CreateTag(const std::string& name, const std::string& message = "");
    bool DeleteTag(const std::string& name);
    bool PushTag(const std::string& name, const std::string& remote = "");

    // Ignore
    bool AddToIgnore(const std::string& pattern);
    bool RemoveFromIgnore(const std::string& pattern);
    std::vector<std::string> GetIgnorePatterns();

    // Submodules
    bool UpdateSubmodules(bool init = false, bool recursive = false);

    // Monitoring
    using StatusCallback = std::function<void(const RepoStatus& status)>;
    void SetStatusCallback(StatusCallback callback);
    void StartMonitoring(int intervalMs = 1000);
    void StopMonitoring();
    void RefreshStatus();

    // C API
    static void* Create();
    static void Destroy(void* instance);
    static int Initialize(void* instance, const char* repoPath);
    static int GetStatus(void* instance, char* buffer, int bufferSize);
    static int GetFileDiff(void* instance, const char* path, int staged, char* buffer, int bufferSize);
    static int GetBlame(void* instance, const char* path, int startLine, int lineCount, char* buffer, int bufferSize);
    static int StageFile(void* instance, const char* path);
    static int Commit(void* instance, const char* message);
    static int DiscardFile(void* instance, const char* path);

private:
    std::string m_repoPath;
    std::string m_gitPath;
    bool m_initialized = false;
    bool m_monitoring = false;
    HANDLE m_monitorThread = nullptr;
    StatusCallback m_statusCallback;

    // Execute git command
    std::string ExecuteGit(const std::string& args, int* exitCode = nullptr);
    bool ExecuteGitBool(const std::string& args);

    // Parsing
    RepoStatus ParseStatus(const std::string& output);
    FileDiff ParseDiff(const std::string& output);
    std::vector<BlameInfo> ParseBlame(const std::string& output);
    CommitInfo ParseCommit(const std::string& output);
    BranchInfo ParseBranch(const std::string& line);

    // Monitoring thread
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();

    // Utility
    std::string EscapePath(const std::string& path);
    std::string QuotePath(const std::string& path);
    std::chrono::system_clock::time_point ParseGitDate(const std::string& dateStr);
    std::string FormatDate(const std::chrono::system_clock::time_point& tp);
    std::string EscapeJson(const std::string& str);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {
    void* GitIntegration_Create();
    void GitIntegration_Destroy(void* instance);
    int GitIntegration_Initialize(void* instance, const char* repoPath);
    int GitIntegration_IsRepo(void* instance);
    int GitIntegration_GetStatus(void* instance, char* buffer, int bufferSize);
    int GitIntegration_GetFileDiff(void* instance, const char* path, int staged, char* buffer, int bufferSize);
    int GitIntegration_GetBlame(void* instance, const char* path, int startLine, int lineCount, char* buffer, int bufferSize);
    int GitIntegration_GetLog(void* instance, int maxCount, char* buffer, int bufferSize);
    int GitIntegration_StageFile(void* instance, const char* path);
    int GitIntegration_UnstageFile(void* instance, const char* path);
    int GitIntegration_Commit(void* instance, const char* message);
    int GitIntegration_DiscardFile(void* instance, const char* path);
    int GitIntegration_Fetch(void* instance);
    int GitIntegration_Pull(void* instance);
    int GitIntegration_Push(void* instance);
}

} // namespace SCM
} // namespace RawrXD
