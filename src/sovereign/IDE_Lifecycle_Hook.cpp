//=============================================================================
// IDE_Lifecycle_Hook.cpp - Task Completion Lifecycle Integration
//=============================================================================

#include "IDE_Lifecycle_Hook.hpp"
#include <iostream>
#include <chrono>

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Singleton Implementation
//=============================================================================

IDE_Lifecycle_Hook& IDE_Lifecycle_Hook::Instance() {
    static IDE_Lifecycle_Hook instance;
    return instance;
}

IDE_Lifecycle_Hook::IDE_Lifecycle_Hook()
    : initialized_(false)
    , sessionActive_(false)
    , taskStartTime_(0)
{
}

IDE_Lifecycle_Hook::~IDE_Lifecycle_Hook() {
    if (initialized_) {
        Shutdown();
    }
}

//=============================================================================
// Initialization
//=============================================================================

void IDE_Lifecycle_Hook::Initialize(const Config& config) {
    if (initialized_) {
        return;
    }
    
    config_ = config;
    
    // Initialize VCS
    if (config_.enableVCS) {
        SovereignVCS::Config vcsConfig;
        vcsConfig.autoPush = config_.pushOnSuccess;
        vcs_.reset(new SovereignVCS(vcsConfig));
    }
    
    // Initialize Checkpoint
    if (config_.enableCheckpoint) {
        SovereignCheckpoint::Config chkConfig;
        chkConfig.filenamePrefix = config_.checkpointPrefix;
        checkpoint_.reset(new SovereignCheckpoint(chkConfig));
    }
    
    initialized_ = true;
    std::cout << "[IDE_Lifecycle_Hook] Initialized\n";
}

void IDE_Lifecycle_Hook::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    // End active session if needed
    if (sessionActive_) {
        OnTaskCancelled();
    }
    
    checkpoint_.reset();
    vcs_.reset();
    
    initialized_ = false;
    std::cout << "[IDE_Lifecycle_Hook] Shutdown\n";
}

//=============================================================================
// Task Lifecycle
//=============================================================================

void IDE_Lifecycle_Hook::OnTaskStart(const std::string& taskName) {
    if (!initialized_) {
        std::cerr << "[IDE_Lifecycle_Hook] Error: Not initialized\n";
        return;
    }
    
    // End any existing session
    if (sessionActive_) {
        OnTaskCancelled();
    }
    
    currentTaskName_ = taskName.empty() ? config_.defaultTaskName : taskName;
    taskStartTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    sessionActive_ = true;
    
    // Perform VCS fork
    if (config_.enableVCS && vcs_) {
        PerformVCSFork(currentTaskName_);
    }
    
    ExecuteLifecycle(LifecycleEvent::TASK_START, "Task started: " + currentTaskName_);
}

void IDE_Lifecycle_Hook::OnTaskComplete(const std::string& message) {
    if (!initialized_ || !sessionActive_) {
        return;
    }
    
    // Calculate duration
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    auto duration = now - taskStartTime_;
    
    // Perform checkpoint
    if (config_.enableCheckpoint && checkpoint_) {
        PerformCheckpoint(currentTaskName_, false);
    }
    
    // Commit VCS
    if (config_.enableVCS && vcs_ && config_.autoCommitOnSuccess) {
        SessionInfo info;
        info.sessionID = currentSessionID_;
        info.branchName = currentBranch_;
        info.forked = true;
        
        std::string commitMsg = message.empty() ? "Task completed: " + currentTaskName_ : message;
        vcs_->CommitSession(info, commitMsg);
        
        if (config_.pushOnSuccess) {
            vcs_->PushSession(info);
        }
    }
    
    ExecuteLifecycle(LifecycleEvent::TASK_COMPLETE, 
        message.empty() ? "Task completed successfully" : message);
    
    ResetState();
}

void IDE_Lifecycle_Hook::OnTaskFailed(const std::string& error) {
    if (!initialized_ || !sessionActive_) {
        return;
    }
    
    // Perform checkpoint (even on failure)
    if (config_.enableCheckpoint && checkpoint_) {
        PerformCheckpoint(currentTaskName_, true);
    }
    
    // Commit VCS with failure note
    if (config_.enableVCS && vcs_ && config_.autoCommitOnFailure) {
        SessionInfo info;
        info.sessionID = currentSessionID_;
        info.branchName = currentBranch_;
        info.forked = true;
        
        std::string commitMsg = "Task failed: " + currentTaskName_;
        if (!error.empty()) {
            commitMsg += " (" + error + ")";
        }
        vcs_->CommitSession(info, commitMsg);
    }
    
    ExecuteLifecycle(LifecycleEvent::TASK_FAILED, 
        error.empty() ? "Task failed" : error);
    
    ResetState();
}

void IDE_Lifecycle_Hook::OnTaskCancelled() {
    if (!initialized_ || !sessionActive_) {
        return;
    }
    
    ExecuteLifecycle(LifecycleEvent::TASK_CANCELLED, "Task cancelled");
    
    ResetState();
}

//=============================================================================
// Manual Operations
//=============================================================================

bool IDE_Lifecycle_Hook::CreateCheckpoint(const std::string& name) {
    if (!initialized_ || !checkpoint_) {
        return false;
    }
    
    std::string filename = config_.checkpointPrefix + name + ".chk";
    return checkpoint_->SaveCheckpoint(filename, currentSessionID_, currentTaskName_);
}

bool IDE_Lifecycle_Hook::RestoreFromCheckpoint(const std::string& name) {
    if (!initialized_ || !checkpoint_) {
        return false;
    }
    
    std::string filename = config_.checkpointPrefix + name + ".chk";
    return checkpoint_->RestoreCheckpoint(filename);
}

bool IDE_Lifecycle_Hook::ResetToMain() {
    if (!initialized_ || !vcs_) {
        return false;
    }
    
    return vcs_->ResetToMain();
}

//=============================================================================
// Session Management
//=============================================================================

std::string IDE_Lifecycle_Hook::GetCurrentSessionID() const {
    return currentSessionID_;
}

std::string IDE_Lifecycle_Hook::GetCurrentBranch() const {
    return currentBranch_;
}

bool IDE_Lifecycle_Hook::IsSessionActive() const {
    return sessionActive_;
}

//=============================================================================
// Callback Registration
//=============================================================================

void IDE_Lifecycle_Hook::SetPreCheckpointCallback(PreCheckpointCallback callback) {
    preCheckpointCallback_ = callback;
}

void IDE_Lifecycle_Hook::SetPostCheckpointCallback(PostCheckpointCallback callback) {
    postCheckpointCallback_ = callback;
}

void IDE_Lifecycle_Hook::SetLifecycleCallback(LifecycleCallback callback) {
    lifecycleCallback_ = callback;
}

//=============================================================================
// Internal Methods
//=============================================================================

void IDE_Lifecycle_Hook::ExecuteLifecycle(LifecycleEvent event, const std::string& message) {
    if (lifecycleCallback_) {
        LifecycleContext ctx;
        ctx.taskID = currentSessionID_;
        ctx.taskName = currentTaskName_;
        ctx.sessionID = currentSessionID_;
        ctx.branchName = currentBranch_;
        ctx.event = event;
        ctx.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() - taskStartTime_;
        ctx.success = (event == LifecycleEvent::TASK_COMPLETE);
        ctx.message = message;
        
        lifecycleCallback_(ctx);
    }
    
    // Log to console
    const char* eventStr = "UNKNOWN";
    switch (event) {
        case LifecycleEvent::TASK_START: eventStr = "START"; break;
        case LifecycleEvent::TASK_COMPLETE: eventStr = "COMPLETE"; break;
        case LifecycleEvent::TASK_FAILED: eventStr = "FAILED"; break;
        case LifecycleEvent::TASK_CANCELLED: eventStr = "CANCELLED"; break;
        case LifecycleEvent::SESSION_END: eventStr = "SESSION_END"; break;
        case LifecycleEvent::CHECKPOINT: eventStr = "CHECKPOINT"; break;
    }
    
    std::cout << "[IDE_Lifecycle] [" << eventStr << "] " << message << "\n";
}

bool IDE_Lifecycle_Hook::PerformCheckpoint(const std::string& taskName, bool isFailure) {
    if (!checkpoint_) {
        return false;
    }
    
    // Pre-checkpoint callback
    if (preCheckpointCallback_ && !preCheckpointCallback_()) {
        return false;
    }
    
    // Generate checkpoint filename
    std::string filename = config_.checkpointPrefix + currentSessionID_ + ".chk";
    
    // Save checkpoint
    bool success = checkpoint_->SaveCheckpoint(filename, currentSessionID_, taskName);
    
    // Post-checkpoint callback
    if (postCheckpointCallback_) {
        postCheckpointCallback_(success);
    }
    
    if (success) {
        std::cout << "[IDE_Lifecycle] Checkpoint saved: " << filename << "\n";
    } else {
        std::cerr << "[IDE_Lifecycle] Checkpoint failed\n";
    }
    
    return success;
}

bool IDE_Lifecycle_Hook::PerformVCSFork(const std::string& taskName) {
    if (!vcs_) {
        return false;
    }
    
    SessionInfo info = vcs_->ForkCurrentSession("");
    
    if (info.forked) {
        currentSessionID_ = info.sessionID;
        currentBranch_ = info.branchName;
        std::cout << "[IDE_Lifecycle] VCS forked: " << info.branchName << "\n";
        return true;
    } else {
        std::cerr << "[IDE_Lifecycle] VCS fork failed\n";
        return false;
    }
}

void IDE_Lifecycle_Hook::ResetState() {
    currentSessionID_.clear();
    currentTaskName_.clear();
    currentBranch_.clear();
    sessionActive_ = false;
    taskStartTime_ = 0;
}

//=============================================================================
// ScopedTaskLifecycle Implementation
//=============================================================================

ScopedTaskLifecycle::ScopedTaskLifecycle(const std::string& taskName)
    : completed_(false)
    , failed_(false)
    , cancelled_(false)
{
    IDE_Lifecycle_Hook::Instance().OnTaskStart(taskName);
}

ScopedTaskLifecycle::~ScopedTaskLifecycle() {
    if (!completed_ && !failed_ && !cancelled_) {
        // Auto-complete on scope exit
        IDE_Lifecycle_Hook::Instance().OnTaskComplete();
    }
}

void ScopedTaskLifecycle::MarkComplete(const std::string& message) {
    completed_ = true;
    IDE_Lifecycle_Hook::Instance().OnTaskComplete(message);
}

void ScopedTaskLifecycle::MarkFailed(const std::string& error) {
    failed_ = true;
    IDE_Lifecycle_Hook::Instance().OnTaskFailed(error);
}

void ScopedTaskLifecycle::MarkCancelled() {
    cancelled_ = true;
    IDE_Lifecycle_Hook::Instance().OnTaskCancelled();
}

} // namespace Sovereign
} // namespace RawrXD
