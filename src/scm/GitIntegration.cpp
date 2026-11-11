// ============================================================================
// GitIntegration.cpp - Production Git SCM Implementation
// ============================================================================
// Full Git integration with diff, blame, commit, status monitoring
// ============================================================================

#include "GitIntegration.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace RawrXD {
namespace SCM {

// ============================================================================
// Construction/Destruction
// ============================================================================

GitIntegration::GitIntegration() = default;

GitIntegration::~GitIntegration() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool GitIntegration::Initialize(const std::string& repoPath) {
    if (m_initialized) return true;

    m_repoPath = repoPath;
    
    // Find git executable
    char gitPath[MAX_PATH];
    if (SearchPathA(nullptr, "git.exe", nullptr, MAX_PATH, gitPath, nullptr) == 0) {
        // Try common locations
        const char* commonPaths[] = {
            "C:\\Program Files\\Git\\bin\\git.exe",
            "C:\\Program Files (x86)\\Git\\bin\\git.exe",
            nullptr
        };
        
        for (int i = 0; commonPaths[i]; i++) {
            if (GetFileAttributesA(commonPaths[i]) != INVALID_FILE_ATTRIBUTES) {
                m_gitPath = commonPaths[i];
                break;
            }
        }
    } else {
        m_gitPath = gitPath;
    }

    if (m_gitPath.empty()) {
        std::cerr << "[Git] Git executable not found" << std::endl;
        return false;
    }

    // Verify it's a git repo
    if (!IsRepo()) {
        std::cerr << "[Git] Not a git repository: " << repoPath << std::endl;
        return false;
    }

    m_initialized = true;
    std::cout << "[Git] Initialized for: " << GetRepoRoot() << std::endl;
    return true;
}

void GitIntegration::Shutdown() {
    StopMonitoring();
    m_initialized = false;
}

// ============================================================================
// Repository Info
// ============================================================================

bool GitIntegration::IsRepo() const {
    if (m_repoPath.empty()) return false;
    
    std::string gitDir = m_repoPath + "\\.git";
    DWORD attrs = GetFileAttributesA(gitDir.c_str());
    return (attrs != INVALID_FILE_ATTRIBUTES);
}

std::string GitIntegration::GetRepoRoot() const {
    return ExecuteGit("rev-parse --show-toplevel");
}

std::string GitIntegration::GetGitDir() const {
    return ExecuteGit("rev-parse --git-dir");
}

// ============================================================================
// Status
// ============================================================================

RepoStatus GitIntegration::GetStatus() {
    RepoStatus status;
    
    // Get branch info
    std::string branchOutput = ExecuteGit("status --porcelain --branch");
    status = ParseStatus(branchOutput);
    
    // Get untracked files
    std::string untracked = ExecuteGit("ls-files --others --exclude-standard");
    std::istringstream untrackedStream(untracked);
    std::string line;
    while (std::getline(untrackedStream, line)) {
        if (!line.empty()) {
            status.untrackedFiles.push_back(line);
            status.unstagedFiles[line] = FileStatus::Untracked;
        }
    }
    
    return status;
}

FileStatus GitIntegration::GetFileStatus(const std::string& path) {
    std::string output = ExecuteGit("status --porcelain " + QuotePath(path));
    if (output.empty()) return FileStatus::Unmodified;
    
    char indexStatus = output[0];
    char workStatus = output[1];
    
    if (indexStatus == 'A' || workStatus == 'A') return FileStatus::Added;
    if (indexStatus == 'M' || workStatus == 'M') return FileStatus::Modified;
    if (indexStatus == 'D' || workStatus == 'D') return FileStatus::Deleted;
    if (indexStatus == 'R') return FileStatus::Renamed;
    if (indexStatus == 'C') return FileStatus::Copied;
    if (indexStatus == 'U' || workStatus == 'U') return FileStatus::Conflict;
    if (indexStatus == '?' || workStatus == '?') return FileStatus::Untracked;
    
    return FileStatus::Unmodified;
}

bool GitIntegration::IsFileTracked(const std::string& path) {
    int exitCode;
    ExecuteGit("ls-files " + QuotePath(path), &exitCode);
    return exitCode == 0;
}

// ============================================================================
// Diff
// ============================================================================

FileDiff GitIntegration::GetFileDiff(const std::string& path, bool staged) {
    std::string cmd = staged ? "diff --cached " : "diff ";
    cmd += QuotePath(path);
    
    std::string output = ExecuteGit(cmd);
    return ParseDiff(output);
}

std::vector<FileDiff> GitIntegration::GetWorkingDiff() {
    std::string output = ExecuteGit("diff");
    
    std::vector<FileDiff> diffs;
    std::istringstream stream(output);
    std::string line;
    std::string currentDiff;
    
    while (std::getline(stream, line)) {
        if (line.substr(0, 4) == "diff" && !currentDiff.empty()) {
            diffs.push_back(ParseDiff(currentDiff));
            currentDiff.clear();
        }
        currentDiff += line + "\n";
    }
    
    if (!currentDiff.empty()) {
        diffs.push_back(ParseDiff(currentDiff));
    }
    
    return diffs;
}

std::vector<FileDiff> GitIntegration::GetStagedDiff() {
    std::string output = ExecuteGit("diff --cached");
    
    std::vector<FileDiff> diffs;
    std::istringstream stream(output);
    std::string line;
    std::string currentDiff;
    
    while (std::getline(stream, line)) {
        if (line.substr(0, 4) == "diff" && !currentDiff.empty()) {
            diffs.push_back(ParseDiff(currentDiff));
            currentDiff.clear();
        }
        currentDiff += line + "\n";
    }
    
    if (!currentDiff.empty()) {
        diffs.push_back(ParseDiff(currentDiff));
    }
    
    return diffs;
}

FileDiff GitIntegration::GetCommitDiff(const std::string& commitHash) {
    std::string output = ExecuteGit("show " + commitHash);
    return ParseDiff(output);
}

FileDiff GitIntegration::GetCommitDiff(const std::string& oldCommit, const std::string& newCommit) {
    std::string output = ExecuteGit("diff " + oldCommit + " " + newCommit);
    return ParseDiff(output);
}

// ============================================================================
// Blame
// ============================================================================

std::vector<BlameInfo> GitIntegration::GetBlame(const std::string& path, int startLine, int lineCount) {
    std::string cmd = "blame --porcelain ";
    if (startLine > 0) {
        cmd += "-L " + std::to_string(startLine) + ",";
        if (lineCount > 0) {
            cmd += std::to_string(startLine + lineCount - 1);
        } else {
            cmd += "+" + std::to_string(lineCount);
        }
        cmd += " ";
    }
    cmd += QuotePath(path);
    
    std::string output = ExecuteGit(cmd);
    return ParseBlame(output);
}

BlameInfo GitIntegration::GetBlameForLine(const std::string& path, int line) {
    auto blame = GetBlame(path, line, 1);
    if (!blame.empty()) return blame[0];
    return BlameInfo();
}

// ============================================================================
// Log
// ============================================================================

std::vector<CommitInfo> GitIntegration::GetLog(int maxCount, const std::string& branch) {
    std::string cmd = "log --format=format:%H|%an|%ae|%ad|%s|%b|%P --date=iso -n " + 
                      std::to_string(maxCount);
    if (!branch.empty()) {
        cmd += " " + branch;
    }
    
    std::string output = ExecuteGit(cmd);
    
    std::vector<CommitInfo> commits;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        commits.push_back(ParseCommit(line));
    }
    
    return commits;
}

CommitInfo GitIntegration::GetCommit(const std::string& hash) {
    std::string cmd = "show --format=format:%H|%an|%ae|%ad|%s|%b|%P --date=iso --no-patch " + hash;
    std::string output = ExecuteGit(cmd);
    return ParseCommit(output);
}

std::vector<CommitInfo> GitIntegration::GetLogForFile(const std::string& path, int maxCount) {
    std::string cmd = "log --format=format:%H|%an|%ae|%ad|%s|%b|%P --date=iso -n " + 
                      std::to_string(maxCount) + " -- " + QuotePath(path);
    
    std::string output = ExecuteGit(cmd);
    
    std::vector<CommitInfo> commits;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        commits.push_back(ParseCommit(line));
    }
    
    return commits;
}

// ============================================================================
// Branches
// ============================================================================

std::vector<BranchInfo> GitIntegration::GetBranches(bool includeRemote) {
    std::string cmd = "branch -vv";
    if (includeRemote) {
        cmd += " -a";
    }
    
    std::string output = ExecuteGit(cmd);
    
    std::vector<BranchInfo> branches;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        branches.push_back(ParseBranch(line));
    }
    
    return branches;
}

BranchInfo GitIntegration::GetCurrentBranch() {
    std::string output = ExecuteGit("branch --show-current");
    BranchInfo branch;
    branch.name = output;
    branch.isCurrent = true;
    return branch;
}

bool GitIntegration::CheckoutBranch(const std::string& branchName, bool create) {
    std::string cmd = "checkout ";
    if (create) cmd += "-b ";
    cmd += branchName;
    return ExecuteGitBool(cmd);
}

bool GitIntegration::DeleteBranch(const std::string& branchName, bool force) {
    std::string cmd = "branch ";
    if (force) cmd += "-D ";
    else cmd += "-d ";
    cmd += branchName;
    return ExecuteGitBool(cmd);
}

bool GitIntegration::MergeBranch(const std::string& branchName) {
    return ExecuteGitBool("merge " + branchName);
}

bool GitIntegration::RebaseBranch(const std::string& branchName) {
    return ExecuteGitBool("rebase " + branchName);
}

// ============================================================================
// Staging
// ============================================================================

bool GitIntegration::StageFile(const std::string& path) {
    return ExecuteGitBool("add " + QuotePath(path));
}

bool GitIntegration::StageFiles(const std::vector<std::string>& paths) {
    std::string cmd = "add";
    for (const auto& path : paths) {
        cmd += " " + QuotePath(path);
    }
    return ExecuteGitBool(cmd);
}

bool GitIntegration::StageAll() {
    return ExecuteGitBool("add -A");
}

bool GitIntegration::UnstageFile(const std::string& path) {
    return ExecuteGitBool("reset HEAD " + QuotePath(path));
}

bool GitIntegration::UnstageFiles(const std::vector<std::string>& paths) {
    std::string cmd = "reset HEAD";
    for (const auto& path : paths) {
        cmd += " " + QuotePath(path);
    }
    return ExecuteGitBool(cmd);
}

bool GitIntegration::UnstageAll() {
    return ExecuteGitBool("reset HEAD");
}

// ============================================================================
// Commit
// ============================================================================

bool GitIntegration::Commit(const std::string& message) {
    std::string cmd = "commit -m \"" + EscapeJson(message) + "\"";
    return ExecuteGitBool(cmd);
}

bool GitIntegration::Commit(const std::string& message, const std::vector<std::string>& paths) {
    std::string cmd = "commit";
    for (const auto& path : paths) {
        cmd += " " + QuotePath(path);
    }
    cmd += " -m \"" + EscapeJson(message) + "\"";
    return ExecuteGitBool(cmd);
}

bool GitIntegration::AmendCommit(const std::string& message) {
    std::string cmd = "commit --amend";
    if (!message.empty()) {
        cmd += " -m \"" + EscapeJson(message) + "\"";
    } else {
        cmd += " --no-edit";
    }
    return ExecuteGitBool(cmd);
}

// ============================================================================
// Discard
// ============================================================================

bool GitIntegration::DiscardFile(const std::string& path) {
    return ExecuteGitBool("checkout -- " + QuotePath(path));
}

bool GitIntegration::DiscardFiles(const std::vector<std::string>& paths) {
    std::string cmd = "checkout --";
    for (const auto& path : paths) {
        cmd += " " + QuotePath(path);
    }
    return ExecuteGitBool(cmd);
}

bool GitIntegration::DiscardAll() {
    return ExecuteGitBool("checkout -- .");
}

// ============================================================================
// Stash
// ============================================================================

bool GitIntegration::Stash(const std::string& message) {
    std::string cmd = "stash push";
    if (!message.empty()) {
        cmd += " -m \"" + EscapeJson(message) + "\"";
    }
    return ExecuteGitBool(cmd);
}

bool GitIntegration::StashPop(int index) {
    return ExecuteGitBool("stash pop stash@{" + std::to_string(index) + "}");
}

bool GitIntegration::StashApply(int index) {
    return ExecuteGitBool("stash apply stash@{" + std::to_string(index) + "}");
}

bool GitIntegration::StashDrop(int index) {
    return ExecuteGitBool("stash drop stash@{" + std::to_string(index) + "}");
}

std::vector<StashEntry> GitIntegration::GetStashList() {
    std::string output = ExecuteGit("stash list --format=format:%H|%s");
    
    std::vector<StashEntry> entries;
    std::istringstream stream(output);
    std::string line;
    int index = 0;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        
        size_t sep = line.find('|');
        if (sep != std::string::npos) {
            StashEntry entry;
            entry.index = index++;
            entry.commitHash = line.substr(0, sep);
            entry.message = line.substr(sep + 1);
            entries.push_back(entry);
        }
    }
    
    return entries;
}

// ============================================================================
// Remote Operations
// ============================================================================

bool GitIntegration::Fetch(const std::string& remote) {
    std::string cmd = "fetch";
    if (!remote.empty()) cmd += " " + remote;
    return ExecuteGitBool(cmd);
}

bool GitIntegration::Pull(const std::string& remote, const std::string& branch) {
    std::string cmd = "pull";
    if (!remote.empty()) {
        cmd += " " + remote;
        if (!branch.empty()) cmd += " " + branch;
    }
    return ExecuteGitBool(cmd);
}

bool GitIntegration::Push(const std::string& remote, const std::string& branch) {
    std::string cmd = "push";
    if (!remote.empty()) {
        cmd += " " + remote;
        if (!branch.empty()) cmd += " " + branch;
    }
    return ExecuteGitBool(cmd);
}

// ============================================================================
// Tags
// ============================================================================

std::vector<std::string> GitIntegration::GetTags() {
    std::string output = ExecuteGit("tag -l");
    
    std::vector<std::string> tags;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (!line.empty()) tags.push_back(line);
    }
    
    return tags;
}

bool GitIntegration::CreateTag(const std::string& name, const std::string& message) {
    std::string cmd = "tag ";
    if (!message.empty()) {
        cmd += "-a -m \"" + EscapeJson(message) + "\" ";
    }
    cmd += name;
    return ExecuteGitBool(cmd);
}

bool GitIntegration::DeleteTag(const std::string& name) {
    return ExecuteGitBool("tag -d " + name);
}

bool GitIntegration::PushTag(const std::string& name, const std::string& remote) {
    std::string cmd = "push ";
    if (!remote.empty()) cmd += remote + " ";
    cmd += name;
    return ExecuteGitBool(cmd);
}

// ============================================================================
// Ignore
// ============================================================================

bool GitIntegration::AddToIgnore(const std::string& pattern) {
    std::string gitignore = m_repoPath + "\\.gitignore";
    
    HANDLE hFile = CreateFileA(gitignore.c_str(), FILE_APPEND_DATA, 
                               FILE_SHARE_READ, nullptr, OPEN_ALWAYS, 
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    std::string line = pattern + "\n";
    DWORD written;
    WriteFile(hFile, line.c_str(), line.size(), &written, nullptr);
    CloseHandle(hFile);
    
    return true;
}

bool GitIntegration::RemoveFromIgnore(const std::string& pattern) {
    std::string gitignore = m_repoPath + "\\.gitignore";
    
    HANDLE hFile = CreateFileA(gitignore.c_str(), GENERIC_READ | GENERIC_WRITE, 
                               0, nullptr, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    DWORD size = GetFileSize(hFile, nullptr);
    std::string content(size, '\0');
    DWORD read;
    ReadFile(hFile, &content[0], size, &read, nullptr);
    
    // Remove pattern
    size_t pos = content.find(pattern);
    if (pos != std::string::npos) {
        size_t end = content.find('\n', pos);
        if (end == std::string::npos) end = content.size();
        content.erase(pos, end - pos + 1);
        
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        SetEndOfFile(hFile);
        DWORD written;
        WriteFile(hFile, content.c_str(), content.size(), &written, nullptr);
    }
    
    CloseHandle(hFile);
    return true;
}

std::vector<std::string> GitIntegration::GetIgnorePatterns() {
    std::string gitignore = m_repoPath + "\\.gitignore";
    
    HANDLE hFile = CreateFileA(gitignore.c_str(), GENERIC_READ, 
                               FILE_SHARE_READ, nullptr, OPEN_EXISTING, 
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    
    DWORD size = GetFileSize(hFile, nullptr);
    std::string content(size, '\0');
    DWORD read;
    ReadFile(hFile, &content[0], size, &read, nullptr);
    CloseHandle(hFile);
    
    std::vector<std::string> patterns;
    std::istringstream stream(content);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (!line.empty() && line[0] != '#') {
            patterns.push_back(line);
        }
    }
    
    return patterns;
}

// ============================================================================
// Submodules
// ============================================================================

bool GitIntegration::UpdateSubmodules(bool init, bool recursive) {
    std::string cmd = "submodule update";
    if (init) cmd += " --init";
    if (recursive) cmd += " --recursive";
    return ExecuteGitBool(cmd);
}

// ============================================================================
// Monitoring
// ============================================================================

void GitIntegration::SetStatusCallback(StatusCallback callback) {
    m_statusCallback = callback;
}

void GitIntegration::StartMonitoring(int intervalMs) {
    if (m_monitoring) return;
    m_monitoring = true;
    
    // Create monitoring thread
    m_monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
}

void GitIntegration::StopMonitoring() {
    m_monitoring = false;
    if (m_monitorThread) {
        WaitForSingleObject(m_monitorThread, 5000);
        CloseHandle(m_monitorThread);
        m_monitorThread = nullptr;
    }
}

void GitIntegration::RefreshStatus() {
    if (m_statusCallback) {
        m_statusCallback(GetStatus());
    }
}

DWORD WINAPI GitIntegration::MonitorThreadProc(LPVOID param) {
    auto* git = static_cast<GitIntegration*>(param);
    git->MonitorLoop();
    return 0;
}

void GitIntegration::MonitorLoop() {
    auto lastCheck = std::chrono::steady_clock::now();
    
    while (m_monitoring) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCheck).count();
        
        if (elapsed >= 1000) {
            RefreshStatus();
            lastCheck = now;
        }
        
        Sleep(100);
    }
}

// ============================================================================
// Command Execution
// ============================================================================

std::string GitIntegration::ExecuteGit(const std::string& args, int* exitCode) {
    if (m_gitPath.empty()) return "";
    
    std::string cmdLine = "\"" + m_gitPath + "\" " + args;
    
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    
    HANDLE hStdOutRead, hStdOutWrite;
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) return "";
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcessA(nullptr, &cmdLine[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, m_repoPath.c_str(), &si, &pi)) {
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return "";
    }
    
    CloseHandle(hStdOutWrite);
    
    // Read output
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    // Wait for process
    WaitForSingleObject(pi.hProcess, 30000);
    
    DWORD exitCodeVal;
    GetExitCodeProcess(pi.hProcess, &exitCodeVal);
    if (exitCode) *exitCode = exitCodeVal;
    
    CloseHandle(hStdOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Remove trailing newline
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    
    return output;
}

bool GitIntegration::ExecuteGitBool(const std::string& args) {
    int exitCode;
    ExecuteGit(args, &exitCode);
    return exitCode == 0;
}

// ============================================================================
// Parsing
// ============================================================================

RepoStatus GitIntegration::ParseStatus(const std::string& output) {
    RepoStatus status;
    
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        
        // Branch line starts with ##
        if (line.substr(0, 2) == "##") {
            // Parse branch info
            size_t space = line.find(' ', 2);
            if (space != std::string::npos) {
                status.branch = line.substr(3, space - 3);
                
                // Check for ahead/behind
                size_t bracket = line.find('[');
                if (bracket != std::string::npos) {
                    size_t close = line.find(']', bracket);
                    std::string aheadBehind = line.substr(bracket + 1, close - bracket - 1);
                    
                    size_t aheadPos = aheadBehind.find("ahead ");
                    if (aheadPos != std::string::npos) {
                        status.ahead = std::stoi(aheadBehind.substr(aheadPos + 6));
                    }
                    
                    size_t behindPos = aheadBehind.find("behind ");
                    if (behindPos != std::string::npos) {
                        status.behind = std::stoi(aheadBehind.substr(behindPos + 7));
                    }
                }
            }
            continue;
        }
        
        // File status
        if (line.size() >= 2) {
            char indexStatus = line[0];
            char workStatus = line[1];
            std::string path = line.substr(3);
            
            // Staged
            if (indexStatus != ' ' && indexStatus != '?') {
                FileStatus fs = FileStatus::Unmodified;
                switch (indexStatus) {
                    case 'M': fs = FileStatus::Modified; break;
                    case 'A': fs = FileStatus::Added; break;
                    case 'D': fs = FileStatus::Deleted; break;
                    case 'R': fs = FileStatus::Renamed; break;
                    case 'C': fs = FileStatus::Copied; break;
                    case 'U': fs = FileStatus::Conflict; break;
                }
                status.stagedFiles[path] = fs;
            }
            
            // Unstaged
            if (workStatus != ' ') {
                FileStatus fs = FileStatus::Unmodified;
                switch (workStatus) {
                    case 'M': fs = FileStatus::Modified; break;
                    case 'D': fs = FileStatus::Deleted; break;
                    case '?': fs = FileStatus::Untracked; break;
                }
                status.unstagedFiles[path] = fs;
            }
        }
    }
    
    return status;
}

FileDiff GitIntegration::ParseDiff(const std::string& output) {
    FileDiff diff;
    
    std::istringstream stream(output);
    std::string line;
    DiffHunk* currentHunk = nullptr;
    
    while (std::getline(stream, line)) {
        if (line.substr(0, 4) == "diff") {
            // New file diff
            if (currentHunk) {
                diff.hunks.push_back(*currentHunk);
                delete currentHunk;
                currentHunk = nullptr;
            }
            
            // Parse file paths
            size_t oldPos = line.find("a/");
            size_t newPos = line.find("b/");
            if (oldPos != std::string::npos && newPos != std::string::npos) {
                diff.oldPath = line.substr(oldPos + 2, newPos - oldPos - 3);
                diff.newPath = line.substr(newPos + 2);
            }
        } else if (line.substr(0, 2) == "@@") {
            // New hunk
            if (currentHunk) {
                diff.hunks.push_back(*currentHunk);
                delete currentHunk;
            }
            
            currentHunk = new DiffHunk();
            currentHunk->header = line;
            
            // Parse hunk header
            size_t oldStart = line.find("-");
            size_t newStart = line.find("+");
            if (oldStart != std::string::npos && newStart != std::string::npos) {
                size_t comma = line.find(",", oldStart);
                if (comma != std::string::npos) {
                    currentHunk->oldStart = std::stoi(line.substr(oldStart + 1, comma - oldStart - 1));
                    currentHunk->oldCount = std::stoi(line.substr(comma + 1, newStart - comma - 2));
                }
                
                comma = line.find(",", newStart);
                if (comma != std::string::npos) {
                    currentHunk->newStart = std::stoi(line.substr(newStart + 1, comma - newStart - 1));
                    currentHunk->newCount = std::stoi(line.substr(comma + 1));
                }
            }
        } else if (currentHunk) {
            // Line in hunk
            if (!line.empty()) {
                char prefix = line[0];
                std::string content = line.substr(1);
                
                switch (prefix) {
                    case '+':
                        currentHunk->lines.push_back({LineChangeType::Added, content});
                        diff.additions++;
                        break;
                    case '-':
                        currentHunk->lines.push_back({LineChangeType::Deleted, content});
                        diff.deletions++;
                        break;
                    case ' ':
                        currentHunk->lines.push_back({LineChangeType::Unchanged, content});
                        break;
                }
            }
        }
    }
    
    if (currentHunk) {
        diff.hunks.push_back(*currentHunk);
        delete currentHunk;
    }
    
    return diff;
}

std::vector<BlameInfo> GitIntegration::ParseBlame(const std::string& output) {
    std::vector<BlameInfo> blame;
    
    std::istringstream stream(output);
    std::string line;
    BlameInfo current;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        
        // New entry starts with commit hash
        if (line[0] != '\t' && line.find(' ') != std::string::npos) {
            if (!current.commitHash.empty()) {
                blame.push_back(current);
            }
            current = BlameInfo();
            
            size_t space = line.find(' ');
            current.commitHash = line.substr(0, space);
            
            // Parse rest of header
            size_t paren = line.find('(');
            if (paren != std::string::npos) {
                size_t close = line.find(')', paren);
                if (close != std::string::npos) {
                    std::string info = line.substr(paren + 1, close - paren - 1);
                    // Parse author and timestamp
                    // Format: author timestamp line
                    std::istringstream infoStream(info);
                    std::getline(infoStream, current.author, ' ');
                    std::string timestamp;
                    std::getline(infoStream, timestamp, ' ');
                    if (!timestamp.empty()) {
                        current.timestamp = ParseGitDate(timestamp);
                    }
                    std::getline(infoStream, current.summary);
                }
            }
        } else if (line[0] == '\t') {
            // Line content
            current.summary = line.substr(1);
        }
    }
    
    if (!current.commitHash.empty()) {
        blame.push_back(current);
    }
    
    return blame;
}

CommitInfo GitIntegration::ParseCommit(const std::string& output) {
    CommitInfo commit;
    
    std::istringstream stream(output);
    std::string line;
    
    if (std::getline(stream, line)) {
        std::istringstream lineStream(line);
        std::string token;
        
        std::getline(lineStream, commit.hash, '|');
        std::getline(lineStream, commit.author, '|');
        std::getline(lineStream, commit.email, '|');
        
        std::string dateStr;
        std::getline(lineStream, dateStr, '|');
        commit.timestamp = ParseGitDate(dateStr);
        
        std::getline(lineStream, commit.summary, '|');
        std::getline(lineStream, commit.body, '|');
        
        std::string parents;
        std::getline(lineStream, parents, '|');
        std::istringstream parentStream(parents);
        std::string parent;
        while (std::getline(parentStream, parent, ' ')) {
            if (!parent.empty()) {
                commit.parentHashes.push_back(parent);
            }
        }
    }
    
    commit.shortHash = commit.hash.substr(0, 7);
    return commit;
}

BranchInfo GitIntegration::ParseBranch(const std::string& line) {
    BranchInfo branch;
    
    // Format: * branchname commit message or
    //         branchname commit message
    std::string trimmed = line;
    if (trimmed.substr(0, 2) == "* ") {
        branch.isCurrent = true;
        trimmed = trimmed.substr(2);
    } else if (trimmed[0] == ' ') {
        trimmed = trimmed.substr(1);
    }
    
    size_t space = trimmed.find(' ');
    if (space != std::string::npos) {
        branch.name = trimmed.substr(0, space);
        
        // Check for [ahead N, behind M]
        size_t bracket = trimmed.find('[');
        if (bracket != std::string::npos) {
            size_t close = trimmed.find(']', bracket);
            std::string aheadBehind = trimmed.substr(bracket + 1, close - bracket - 1);
            
            size_t aheadPos = aheadBehind.find("ahead ");
            if (aheadPos != std::string::npos) {
                branch.ahead = std::stoi(aheadBehind.substr(aheadPos + 6));
            }
            
            size_t behindPos = aheadBehind.find("behind ");
            if (behindPos != std::string::npos) {
                branch.behind = std::stoi(aheadBehind.substr(behindPos + 7));
            }
        }
    }
    
    return branch;
}

// ============================================================================
// Utility
// ============================================================================

std::string GitIntegration::EscapePath(const std::string& path) {
    std::string result;
    for (char c : path) {
        if (c == ' ' || c == '"' || c == '\\') {
            result += '\\';
        }
        result += c;
    }
    return result;
}

std::string GitIntegration::QuotePath(const std::string& path) {
    return "\"" + EscapePath(path) + "\"";
}

std::chrono::system_clock::time_point GitIntegration::ParseGitDate(const std::string& dateStr) {
    // Parse ISO 8601 format
    std::tm tm = {};
    std::istringstream ss(dateStr);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    if (ss.fail()) {
        return std::chrono::system_clock::now();
    }
    
    return std::chrono::system_clock::from_time_t(std::mktime(&tm));
}

std::string GitIntegration::FormatDate(const std::chrono::system_clock::time_point& tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::tm tm;
    localtime_s(&tm, &time);
    
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::string GitIntegration::EscapeJson(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    result += c;
                } else {
                    char buf[8];
                    sprintf_s(buf, "\\u%04x", (unsigned char)c);
                    result += buf;
                }
        }
    }
    return result;
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

void* GitIntegration_Create() {
    return new GitIntegration();
}

void GitIntegration_Destroy(void* instance) {
    delete static_cast<GitIntegration*>(instance);
}

int GitIntegration_Initialize(void* instance, const char* repoPath) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->Initialize(repoPath) ? 1 : 0;
}

int GitIntegration_IsRepo(void* instance) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->IsRepo() ? 1 : 0;
}

int GitIntegration_GetStatus(void* instance, char* buffer, int bufferSize) {
    auto* git = static_cast<GitIntegration*>(instance);
    RepoStatus status = git->GetStatus();
    
    std::string json = "{";
    json += "\"branch\":\"" + status.branch + "\",";
    json += "\"ahead\":" + std::to_string(status.ahead) + ",";
    json += "\"behind\":" + std::to_string(status.behind) + ",";
    json += "\"staged\":[";
    bool first = true;
    for (const auto& pair : status.stagedFiles) {
        if (!first) json += ",";
        first = false;
        json += "\"" + pair.first + "\"";
    }
    json += "],";
    json += "\"unstaged\":[";
    first = true;
    for (const auto& pair : status.unstagedFiles) {
        if (!first) json += ",";
        first = false;
        json += "\"" + pair.first + "\"";
    }
    json += "]}";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(buffer, json.c_str(), copySize);
    buffer[copySize] = '\0';
    
    return copySize;
}

int GitIntegration_GetFileDiff(void* instance, const char* path, int staged, char* buffer, int bufferSize) {
    auto* git = static_cast<GitIntegration*>(instance);
    FileDiff diff = git->GetFileDiff(path, staged != 0);
    
    std::string json = "{";
    json += "\"oldPath\":\"" + diff.oldPath + "\",";
    json += "\"newPath\":\"" + diff.newPath + "\",";
    json += "\"additions\":" + std::to_string(diff.additions) + ",";
    json += "\"deletions\":" + std::to_string(diff.deletions) + ",";
    json += "\"hunks\":[";
    
    bool firstHunk = true;
    for (const auto& hunk : diff.hunks) {
        if (!firstHunk) json += ",";
        firstHunk = false;
        json += "{";
        json += "\"oldStart\":" + std::to_string(hunk.oldStart) + ",";
        json += "\"oldCount\":" + std::to_string(hunk.oldCount) + ",";
        json += "\"newStart\":" + std::to_string(hunk.newStart) + ",";
        json += "\"newCount\":" + std::to_string(hunk.newCount) + ",";
        json += "\"lines\":[";
        
        bool firstLine = true;
        for (const auto& line : hunk.lines) {
            if (!firstLine) json += ",";
            firstLine = false;
            json += "{";
            json += "\"type\":" + std::to_string(static_cast<int>(line.first)) + ",";
            json += "\"text\":\"" + git->EscapeJson(line.second) + "\"";
            json += "}";
        }
        json += "]}";
    }
    json += "]}";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(buffer, json.c_str(), copySize);
    buffer[copySize] = '\0';
    
    return copySize;
}

int GitIntegration_GetBlame(void* instance, const char* path, int startLine, int lineCount, char* buffer, int bufferSize) {
    auto* git = static_cast<GitIntegration*>(instance);
    auto blame = git->GetBlame(path, startLine, lineCount);
    
    std::string json = "[";
    bool first = true;
    for (const auto& info : blame) {
        if (!first) json += ",";
        first = false;
        json += "{";
        json += "\"commit\":\"" + info.commitHash + "\",";
        json += "\"author\":\"" + info.author + "\",";
        json += "\"summary\":\"" + git->EscapeJson(info.summary) + "\"";
        json += "}";
    }
    json += "]";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(buffer, json.c_str(), copySize);
    buffer[copySize] = '\0';
    
    return copySize;
}

int GitIntegration_GetLog(void* instance, int maxCount, char* buffer, int bufferSize) {
    auto* git = static_cast<GitIntegration*>(instance);
    auto commits = git->GetLog(maxCount);
    
    std::string json = "[";
    bool first = true;
    for (const auto& commit : commits) {
        if (!first) json += ",";
        first = false;
        json += "{";
        json += "\"hash\":\"" + commit.hash + "\",";
        json += "\"shortHash\":\"" + commit.shortHash + "\",";
        json += "\"author\":\"" + commit.author + "\",";
        json += "\"summary\":\"" + git->EscapeJson(commit.summary) + "\"";
        json += "}";
    }
    json += "]";
    
    int copySize = (json.size() < static_cast<size_t>(bufferSize - 1)) ? 
                   static_cast<int>(json.size()) : (bufferSize - 1);
    memcpy(buffer, json.c_str(), copySize);
    buffer[copySize] = '\0';
    
    return copySize;
}

int GitIntegration_StageFile(void* instance, const char* path) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->StageFile(path) ? 1 : 0;
}

int GitIntegration_UnstageFile(void* instance, const char* path) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->UnstageFile(path) ? 1 : 0;
}

int GitIntegration_Commit(void* instance, const char* message) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->Commit(message) ? 1 : 0;
}

int GitIntegration_DiscardFile(void* instance, const char* path) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->DiscardFile(path) ? 1 : 0;
}

int GitIntegration_Fetch(void* instance) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->Fetch() ? 1 : 0;
}

int GitIntegration_Pull(void* instance) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->Pull() ? 1 : 0;
}

int GitIntegration_Push(void* instance) {
    auto* git = static_cast<GitIntegration*>(instance);
    return git->Push() ? 1 : 0;
}

} // extern "C"

} // namespace SCM
} // namespace RawrXD
