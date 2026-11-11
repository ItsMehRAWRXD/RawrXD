//=============================================================================
// IDE_Lifecycle_Hook.hpp - Task Completion Lifecycle Integration
// Triggers VCS forking and checkpointing on task completion
//=============================================================================

#pragma once

#include "SovereignVCS.hpp"
#include "SovereignCheckpoint.hpp"
#include <functional>
#include <string>
#include <memory>

namespace RawrXD {
namespace Sovereign {

//=============================================================================
// Lifecycle Event Types
//=============================================================================

enum class LifecycleEvent {
    TASK_START,      // Task begins execution
    TASK_COMPLETE,   // Task completed successfully
    TASK_FAILED,     // Task failed
    TASK_CANCELLED,  // Task was cancelled
    SESSION_END,     // Session is ending
    CHECKPOINT       // Manual checkpoint requested
};

struct LifecycleContext {
    std::string taskID;
    std::string taskName;
    std::string sessionID;
    std::string branchName;
    LifecycleEvent event;
    uint64_t durationMs;
    bool success;
    std::string message;
};

//=============================================================================
// Lifecycle Callback Interface
//=============================================================================

using LifecycleCallback = std::function<void(const LifecycleContext&)>;
using PreCheckpointCallback = std::function<bool()>;  // Return false to abort
using PostCheckpointCallback = std::function<void(bool success)>;

//=============================================================================
// IDE Lifecycle Hook
//=============================================================================

class IDE_Lifecycle_Hook {
public:
    struct Config {
        bool enableVCS = true;
        bool enableCheckpoint = true;
        bool autoCommitOnSuccess = true;
        bool autoCommitOnFailure = true;
        bool pushOnSuccess = false;
        std::string checkpointPrefix = "autosave_";
        std::string defaultTaskName = "sovereign_task";
    };
    
    // Singleton access
    static IDE_Lifecycle_Hook& Instance();
    
    // Configuration
    void Initialize(const Config& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Task Lifecycle
    void OnTaskStart(const std::string& taskName);
    void OnTaskComplete(const std::string& message = "");
    void OnTaskFailed(const std::string& error = "");
    void OnTaskCancelled();
    
    // Manual Operations
    bool CreateCheckpoint(const std::string& name);
    bool RestoreFromCheckpoint(const std::string& name);
    bool ResetToMain();
    
    // Session Management
    std::string GetCurrentSessionID() const;
    std::string GetCurrentBranch() const;
    bool IsSessionActive() const;
    
    // Callback Registration
    void SetPreCheckpointCallback(PreCheckpointCallback callback);
    void SetPostCheckpointCallback(PostCheckpointCallback callback);
    void SetLifecycleCallback(LifecycleCallback callback);
    
    // Component Access
    SovereignVCS& GetVCS() { return *vcs_; }
    SovereignCheckpoint& GetCheckpoint() { return *checkpoint_; }
    
private:
    IDE_Lifecycle_Hook();
    ~IDE_Lifecycle_Hook();
    
    // Non-copyable
    IDE_Lifecycle_Hook(const IDE_Lifecycle_Hook&) = delete;
    IDE_Lifecycle_Hook& operator=(const IDE_Lifecycle_Hook&) = delete;
    
    bool initialized_;
    Config config_;
    
    std::unique_ptr<SovereignVCS> vcs_;
    std::unique_ptr<SovereignCheckpoint> checkpoint_;
    
    // Current session state
    std::string currentSessionID_;
    std::string currentTaskName_;
    std::string currentBranch_;
    bool sessionActive_;
    uint64_t taskStartTime_;
    
    // Callbacks
    PreCheckpointCallback preCheckpointCallback_;
    PostCheckpointCallback postCheckpointCallback_;
    LifecycleCallback lifecycleCallback_;
    
    // Internal methods
    void ExecuteLifecycle(LifecycleEvent event, const std::string& message);
    bool PerformCheckpoint(const std::string& taskName, bool isFailure);
    bool PerformVCSFork(const std::string& taskName);
    void ResetState();
};

//=============================================================================
// Scoped Task Guard
// RAII wrapper for automatic lifecycle management
//=============================================================================

class ScopedTaskLifecycle {
public:
    explicit ScopedTaskLifecycle(const std::string& taskName);
    ~ScopedTaskLifecycle();
    
    void MarkComplete(const std::string& message = "");
    void MarkFailed(const std::string& error = "");
    void MarkCancelled();
    
private:
    bool completed_;
    bool failed_;
    bool cancelled_;
};

//=============================================================================
// Convenience Macros
//=============================================================================

#define SOVEREIGN_TASK(name) \
    RawrXD::Sovereign::ScopedTaskLifecycle _sov_task_##__LINE__(name)

#define SOVEREIGN_TASK_COMPLETE(msg) \
    _sov_task_##__LINE__.MarkComplete(msg)

#define SOVEREIGN_TASK_FAILED(err) \
    _sov_task_##__LINE__.MarkFailed(err)

} // namespace Sovereign
} // namespace RawrXD
