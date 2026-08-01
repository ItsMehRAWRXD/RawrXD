// ============================================================================
// AutonomousBuildLoop.hpp - Self-Driving Build Agent
// The core state machine that transforms RawrXD from AI-assisted to AI-engineer
// ============================================================================

#pragma once

#include "CEOAgent.hpp"
#include <atomic>
#include <thread>
#include <condition_variable>
#include <queue>
#include <map>

namespace RawrXD {
namespace Agents {

// ============================================================================
// Build Loop States
// ============================================================================
enum class BuildState {
    IDLE,
    PLANNING,
    ANALYZING,
    CODING,
    BUILDING,
    TESTING,
    DEBUGGING,
    VALIDATING,
    COMMITTING,
    DONE,
    FAILED,
    PAUSED
};

// ============================================================================
// Build Event Types
// ============================================================================
enum class BuildEventType {
    TASK_STARTED,
    FILE_CREATED,
    FILE_MODIFIED,
    BUILD_STARTED,
    BUILD_PROGRESS,
    BUILD_FAILED,
    BUILD_SUCCEEDED,
    TEST_STARTED,
    TEST_FAILED,
    TEST_PASSED,
    ERROR_FOUND,
    ERROR_FIXED,
    PATCH_APPLIED,
    CHECKPOINT_CREATED,
    STATE_CHANGED
};

struct BuildEvent {
    BuildEventType type;
    std::string taskId;
    std::string message;
    std::string details;
    float progress = 0.0f;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Build Configuration
// ============================================================================
struct BuildConfig {
    uint32_t maxRetries = 3;
    uint32_t maxConsecutiveFailures = 5;
    uint32_t buildTimeoutSec = 300;
    uint32_t testTimeoutSec = 600;
    bool requireTestsPass = true;
    bool requireBuildClean = true;
    bool autoCommit = false;
    bool dryRun = false;
    bool confirmDestructive = true;
    uint32_t maxFilesPerTask = 50;
};

// ============================================================================
// Build Result
// ============================================================================
struct BuildResult {
    bool success = false;
    BuildState finalState = BuildState::IDLE;
    std::vector<std::string> completedTasks;
    std::vector<std::string> failedTasks;
    std::vector<std::string> modifiedFiles;
    std::string summary;
    uint32_t attempts = 0;
    double durationSec = 0.0;
};

// ============================================================================
// Event Listener Interface
// ============================================================================
class IBuildEventListener {
public:
    virtual ~IBuildEventListener() = default;
    virtual void OnBuildEvent(const BuildEvent& event) = 0;
};

// ============================================================================
// Autonomous Build Loop
// ============================================================================
class AutonomousBuildLoop {
public:
    AutonomousBuildLoop();
    ~AutonomousBuildLoop();
    
    bool Initialize(CEOAgent* ceoAgent, ToolRegistry* tools, AgentMemory* memory);
    BuildResult ExecuteGoal(const std::string& goal, const BuildConfig& config = {});
    BuildResult ExecuteTask(const Task& task);
    
    void Pause();
    void Resume();
    void Abort();
    void Checkpoint(const std::string& name);
    void Rollback(const std::string& checkpoint);
    
    BuildState GetCurrentState() const { return currentState_.load(); }
    std::string GetCurrentStateString() const;
    bool IsRunning() const { return running_.load(); }
    
    void AddEventListener(IBuildEventListener* listener);
    void RemoveEventListener(IBuildEventListener* listener);
    
    struct Stats {
        uint64_t totalBuilds = 0;
        uint64_t successfulBuilds = 0;
        uint64_t failedBuilds = 0;
        uint64_t totalRetries = 0;
        double avgBuildTimeSec = 0.0;
        double successRate = 0.0;
    };
    Stats GetStats() const;

private:
    void RunStateMachine();
    void TransitionTo(BuildState newState);
    bool ExecuteStateAction();
    
    bool HandlePlanning();
    bool HandleAnalyzing();
    bool HandleCoding();
    bool HandleBuilding();
    bool HandleTesting();
    bool HandleDebugging();
    bool HandleValidating();
    bool HandleCommitting();
    
    bool PlanTasks(const std::string& goal);
    bool AnalyzeCurrentState();
    bool GenerateCode();
    bool RunBuild();
    bool RunTests();
    bool DebugFailures();
    bool ReadFileContent(const std::string& path, std::string& content);
    bool ValidateChanges();
    bool CommitChanges();
    
    bool AttemptRecovery();
    void LogFailure(const std::string& stage, const std::string& error);
    void EmitEvent(const BuildEvent& event);
    void EmitEvent(BuildEventType type, const std::string& message);
    
    CEOAgent* ceoAgent_ = nullptr;
    ToolRegistry* tools_ = nullptr;
    AgentMemory* memory_ = nullptr;
    
    std::atomic<BuildState> currentState_{BuildState::IDLE};
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> abortRequested_{false};
    
    std::queue<Task> taskQueue_;
    std::vector<Task> completedTasks_;
    std::vector<Task> failedTasks_;
    Task* currentTask_ = nullptr;
    
    BuildConfig config_;
    std::string currentGoal_;
    
    std::unique_ptr<std::thread> workerThread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    std::vector<IBuildEventListener*> listeners_;
    Stats stats_;
    std::chrono::system_clock::time_point buildStartTime_;
    uint32_t consecutiveFailures_ = 0;
    uint32_t retryCount_ = 0;
    
    // Fix memory: maps error types to known fix patterns
    std::map<std::string, std::string> fixMemory_;
};

// ============================================================================
// Console Event Listener
// ============================================================================
class ConsoleBuildListener : public IBuildEventListener {
public:
    void OnBuildEvent(const BuildEvent& event) override;
};

} // namespace Agents
} // namespace RawrXD
