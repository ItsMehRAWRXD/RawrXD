// ============================================================================
// CEOAgent.hpp — Chief Executive Officer Agent
// Top-level autonomous orchestrator that manages the entire project lifecycle
// Capable of: planning, execution, self-correction, and completion
// ============================================================================
#pragma once

#include "CEOAgentTypes.hpp"
#include "AutonomousBuildLoop.hpp"
#include "ContextEngine.hpp"
#include "ModelRouter.hpp"
#include "ProjectState.hpp"
#include "../agentic/AgentOrchestrator.h"
#include "../agentic/ToolRegistry.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace CEO {

using json = nlohmann::json;

// ============================================================================
// CEO Agent — The Brain of RawrXD
// ============================================================================
class CEOAgent {
public:
    CEOAgent();
    ~CEOAgent();
    
    // Initialization
    bool Initialize(const CEOConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Core Operations
    // Start a new autonomous project session
    Goal StartProject(const std::string& goalDescription);
    
    // Continue from where we left off
    Goal ContinueProject();
    
    // Execute a specific goal
    Goal ExecuteGoal(const std::string& goalDescription);
    
    // Execute with full autonomy (the "overnight builder" mode)
    void ExecuteAutonomous(const std::string& highLevelGoal);
    
    // Pause/Resume
    void Pause();
    void Resume();
    bool IsPaused() const { return m_paused.load(); }
    
    // Cancel current operation
    void Cancel();
    bool IsRunning() const { return m_running.load(); }
    
    // State queries
    const ProjectState& GetProjectState() const;
    std::vector<Task> GetTaskQueue() const;
    Task GetCurrentTask() const;
    Goal GetCurrentGoal() const;
    
    // Callbacks
    void SetProgressCallback(ProgressCallback cb) { m_progressCb = cb; }
    void SetTaskCallback(TaskCallback cb) { m_taskCb = cb; }
    void SetCompletionCallback(CompletionCallback cb) { m_completionCb = cb; }
    
    // Manual control (for IDE integration)
    bool ApproveTask(const std::string& taskId);
    bool RejectTask(const std::string& taskId, const std::string& reason);
    bool ModifyTask(const std::string& taskId, const json& modifications);
    
    // Export/Import state
    bool SaveState(const std::string& path);
    bool LoadState(const std::string& path);
    
    // Get detailed report
    json GenerateReport() const;
    
private:
    // Core loop
    void RunCEOLoop();
    void ProcessGoal(Goal& goal);
    
    // Phase handlers
    bool Phase_Analyze(Goal& goal);
    bool Phase_Plan(Goal& goal);
    bool Phase_Execute(Goal& goal);
    bool Phase_Validate(Goal& goal);
    bool Phase_Complete(Goal& goal);
    
    // Task execution
    bool ExecuteTask(Task& task);
    bool ExecuteAnalyzeTask(Task& task);
    bool ExecutePlanTask(Task& task);
    bool ExecuteCodeTask(Task& task);
    bool ExecuteBuildTask(Task& task);
    bool ExecuteTestTask(Task& task);
    bool ExecuteDebugTask(Task& task);
    bool ExecuteReviewTask(Task& task);
    bool ExecuteCommitTask(Task& task);
    
    // Recovery
    bool HandleFailure(Task& task, const std::string& error);
    bool EscalateFailure(Task& task);
    bool Rollback(Task& task);
    
    // Utilities
    std::string GenerateId();
    void ReportProgress(const std::string& stage, const std::string& message, float percent);
    void ReportTask(const Task& task);
    void ReportCompletion(const Goal& goal, bool success);
    
    // Tool integration
    bool InvokeTool(const std::string& toolName, const json& args, json& result);
    
private:
    // Configuration
    CEOConfig m_config;
    std::atomic<bool> m_initialized{false};
    
    // State
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    std::atomic<bool> m_cancelled{false};
    std::atomic<int> m_iteration{0};
    
    // Current operation
    Goal m_currentGoal;
    Task m_currentTask;
    std::vector<Task> m_taskQueue;
    mutable std::mutex m_stateMutex;
    
    // Subsystems
    std::unique_ptr<ProjectState> m_projectState;
    std::unique_ptr<AutonomousBuildLoop> m_buildLoop;
    std::unique_ptr<ContextEngine> m_contextEngine;
    std::unique_ptr<ModelRouter> m_modelRouter;
    std::unique_ptr<Agent::AgentOrchestrator> m_agentOrchestrator;
    
    // Threading
    std::thread m_workerThread;
    
    // Callbacks
    ProgressCallback m_progressCb;
    TaskCallback m_taskCb;
    CompletionCallback m_completionCb;
    
    // Memory
    std::vector<std::string> m_conversationHistory;
};

} // namespace CEO
} // namespace RawrXD
