//=============================================================================
// SovereignVCS.hpp - Git Forking Engine for Session Management
// Automates branch creation to preserve each autonomous development session
//=============================================================================

#pragma once

#include <string>
#include <chrono>
#include <cstdio>
#include <array>
#include <memory>
#include <stdexcept>

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Session Info
//=============================================================================

struct SessionInfo {
    std::string sessionID;
    std::string branchName;
    std::string timestamp;
    std::string checkpointFile;
    bool forked;
    bool checkpointed;
    
    SessionInfo() : forked(false), checkpointed(false) {}
};

//=============================================================================
// SovereignVCS - Git Forking Engine
//=============================================================================

class SovereignVCS {
public:
    // Configuration
    struct Config {
        std::string branchPrefix = "session_";
        std::string remoteName = "origin";
        bool autoPush = false;
        bool createTag = true;
    };
    
    // Initialize VCS with configuration
    explicit SovereignVCS(const Config& config = Config());
    
    // Core Operations
    SessionInfo ForkCurrentSession(const std::string& sessionID);
    bool CommitSession(const SessionInfo& info, const std::string& message);
    bool PushSession(const SessionInfo& info);
    bool CheckoutBranch(const std::string& branchName);
    bool ResetToMain();
    
    // Utility
    bool IsGitRepository() const;
    std::string GetCurrentBranch() const;
    std::string GenerateSessionID() const;
    
    // Session Management
    std::vector<SessionInfo> ListSessionBranches() const;
    bool DeleteSessionBranch(const std::string& branchName);
    
private:
    Config config_;
    
    // Platform-specific command execution
    int ExecuteCommand(const std::string& cmd, std::string& output) const;
    bool ExecuteGitCommand(const std::string& args) const;
    std::string ExecuteGitCommandWithOutput(const std::string& args) const;
};

//=============================================================================
// Scoped Session Guard
// Automatically forks and checkpoints on destruction
//=============================================================================

class ScopedSessionGuard {
public:
    explicit ScopedSessionGuard(SovereignVCS& vcs, const std::string& taskName);
    ~ScopedSessionGuard();
    
    void MarkComplete();
    void MarkFailed();
    
    const SessionInfo& GetInfo() const { return info_; }
    
private:
    SovereignVCS& vcs_;
    SessionInfo info_;
    bool completed_;
    bool failed_;
};

} // namespace Sovereign
} // namespace RawrXD
