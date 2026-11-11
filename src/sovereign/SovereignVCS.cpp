//=============================================================================
// SovereignVCS.cpp - Git Forking Engine Implementation
//=============================================================================

#include "SovereignVCS.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Constructor
//=============================================================================

SovereignVCS::SovereignVCS(const Config& config)
    : config_(config)
{
}

//=============================================================================
// Core Operations
//=============================================================================

SessionInfo SovereignVCS::ForkCurrentSession(const std::string& sessionID) {
    SessionInfo info;
    info.sessionID = sessionID.empty() ? GenerateSessionID() : sessionID;
    info.branchName = config_.branchPrefix + info.sessionID;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
    info.timestamp = ss.str();
    
    // Check if we're in a git repository
    if (!IsGitRepository()) {
        info.forked = false;
        return info;
    }
    
    // Stage any current changes
    ExecuteGitCommand("add -A");
    
    // Create and checkout new branch
    std::string createCmd = "checkout -b " + info.branchName;
    info.forked = ExecuteGitCommand(createCmd);
    
    if (info.forked && config_.createTag) {
        // Create a tag for this session start
        std::string tagName = "start_" + info.sessionID;
        ExecuteGitCommand("tag " + tagName);
    }
    
    return info;
}

bool SovereignVCS::CommitSession(const SessionInfo& info, const std::string& message) {
    if (!info.forked) return false;
    
    // Stage all changes
    if (!ExecuteGitCommand("add -A")) {
        return false;
    }
    
    // Commit with message
    std::string commitCmd = "commit -m \"" + message + " [Session: " + info.sessionID + "]\"";
    return ExecuteGitCommand(commitCmd);
}

bool SovereignVCS::PushSession(const SessionInfo& info) {
    if (!info.forked || !config_.autoPush) return false;
    
    std::string pushCmd = "push " + config_.remoteName + " " + info.branchName;
    return ExecuteGitCommand(pushCmd);
}

bool SovereignVCS::CheckoutBranch(const std::string& branchName) {
    std::string cmd = "checkout " + branchName;
    return ExecuteGitCommand(cmd);
}

bool SovereignVCS::ResetToMain() {
    // Stash any changes
    ExecuteGitCommand("stash push -m \"Auto-stash before reset\"");
    
    // Try main first, then master
    if (ExecuteGitCommand("checkout main")) {
        return true;
    }
    return ExecuteGitCommand("checkout master");
}

//=============================================================================
// Utility
//=============================================================================

bool SovereignVCS::IsGitRepository() const {
    std::string output;
    int result = ExecuteCommand("git rev-parse --git-dir", output);
    return result == 0;
}

std::string SovereignVCS::GetCurrentBranch() const {
    return ExecuteGitCommandWithOutput("rev-parse --abbrev-ref HEAD");
}

std::string SovereignVCS::GenerateSessionID() const {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    // Generate short hash from timestamp
    std::stringstream ss;
    ss << std::hex << (ms & 0xFFFFFFFF);
    std::string hash = ss.str();
    
    // Pad to 8 characters
    while (hash.length() < 8) {
        hash = "0" + hash;
    }
    
    return hash.substr(0, 8);
}

std::vector<SessionInfo> SovereignVCS::ListSessionBranches() const {
    std::vector<SessionInfo> sessions;
    
    std::string output = ExecuteGitCommandWithOutput(
        "branch --list \"" + config_.branchPrefix + "*\" --format=\"%(refname:short)\"");
    
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find(config_.branchPrefix) == 0) {
            SessionInfo info;
            info.branchName = line;
            info.sessionID = line.substr(config_.branchPrefix.length());
            sessions.push_back(info);
        }
    }
    
    return sessions;
}

bool SovereignVCS::DeleteSessionBranch(const std::string& branchName) {
    // Delete local branch
    if (!ExecuteGitCommand("branch -D " + branchName)) {
        return false;
    }
    
    // Delete remote branch if autoPush is enabled
    if (config_.autoPush) {
        ExecuteGitCommand("push " + config_.remoteName + " --delete " + branchName);
    }
    
    return true;
}

//=============================================================================
// Command Execution
//=============================================================================

int SovereignVCS::ExecuteCommand(const std::string& cmd, std::string& output) const {
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return -1;
    }
    
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    
    PROCESS_INFORMATION pi = { 0 };
    
    std::string fullCmd = "cmd /c " + cmd;
    
    if (!CreateProcessA(NULL, (LPSTR)fullCmd.c_str(), NULL, NULL, TRUE, 
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return -1;
    }
    
    CloseHandle(hWrite);
    
    // Read output
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    
    return static_cast<int>(exitCode);
#else
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return -1;
    
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    return pclose(pipe);
#endif
}

bool SovereignVCS::ExecuteGitCommand(const std::string& args) const {
    std::string output;
    int result = ExecuteCommand("git " + args, output);
    return result == 0;
}

std::string SovereignVCS::ExecuteGitCommandWithOutput(const std::string& args) const {
    std::string output;
    ExecuteCommand("git " + args, output);
    
    // Trim whitespace
    size_t start = output.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = output.find_last_not_of(" \t\n\r");
    return output.substr(start, end - start + 1);
}

//=============================================================================
// ScopedSessionGuard Implementation
//=============================================================================

ScopedSessionGuard::ScopedSessionGuard(SovereignVCS& vcs, const std::string& taskName)
    : vcs_(vcs)
    , completed_(false)
    , failed_(false)
{
    // Fork session at start
    info_ = vcs_.ForkCurrentSession("");
    
    if (info_.forked) {
        std::printf("[SovereignVCS] Session forked: %s\n", info_.branchName.c_str());
    }
}

ScopedSessionGuard::~ScopedSessionGuard() {
    if (!completed_ && !failed_) {
        // Auto-commit on destruction if not explicitly marked
        if (info_.forked) {
            vcs_.CommitSession(info_, "Auto-commit: Session completed");
            std::printf("[SovereignVCS] Session committed: %s\n", info_.branchName.c_str());
        }
    }
}

void ScopedSessionGuard::MarkComplete() {
    completed_ = true;
    if (info_.forked) {
        vcs_.CommitSession(info_, "Task completed successfully");
        // Note: Push would require config access - simplified for now
    }
}

void ScopedSessionGuard::MarkFailed() {
    failed_ = true;
    if (info_.forked) {
        vcs_.CommitSession(info_, "Task failed - checkpoint saved");
    }
}

} // namespace Sovereign
} // namespace RawrXD
