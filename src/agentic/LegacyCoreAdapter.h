/**
 * @file LegacyCoreAdapter.h
 * @brief Adapter that wraps existing agentic code behind the new Core interface
 * 
 * Part of Phase 2: Adapter Layer Implementation
 * Allows gradual migration from legacy agentic code to unified Core API
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "Core.h"

// Forward declarations for legacy components
class AgenticEngine;
class TaskExecutor;
class ToolManager;

namespace RawrXD {
namespace Agentic {

/**
 * @brief Adapter that wraps legacy agentic components behind the new Core interface
 * 
 * This adapter allows existing code to continue working while providing
 * the new unified Core API. Gradually, the internal implementation will
 * be replaced with the new CoreImpl.
 * 
 * Usage:
 *   auto legacyEngine = GetExistingAgenticEngine();
 *   auto core = LegacyCoreAdapter::Create(legacyEngine);
 *   core->SubmitTask(task);  // Uses legacy engine internally
 */
class LegacyCoreAdapter : public Core {
public:
    /**
     * @brief Create adapter wrapping existing agentic engine
     * @param legacyEngine Existing agentic engine instance
     * @param config Core configuration
     * @return Adapter instance implementing Core interface
     */
    static std::unique_ptr<Core> Create(
        AgenticEngine* legacyEngine,
        const CoreConfig& config = CoreConfig{});

    /**
     * @brief Create with default configuration
     * @param legacyEngine Existing agentic engine instance  
     * @return Adapter instance
     */
    static std::unique_ptr<Core> Create(AgenticEngine* legacyEngine);

    /**
     * @brief Destructor
     */
    ~LegacyCoreAdapter() override;

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    
    bool Initialize() override;
    bool Shutdown(std::chrono::milliseconds timeout) override;
    bool IsInitialized() const override;

    // ------------------------------------------------------------------------
    // Task Execution - Async
    // ------------------------------------------------------------------------
    
    std::future<TaskResult> SubmitTask(const Task& task) override;
    std::future<TaskResult> SubmitTask(
        const Task& task,
        TaskProgressCallback onProgress,
        TaskOutputCallback onOutput) override;
    std::vector<std::future<TaskResult>> SubmitBatch(
        const std::vector<Task>& tasks) override;

    // ------------------------------------------------------------------------
    // Task Execution - Sync
    // ------------------------------------------------------------------------
    
    TaskResult ExecuteSync(const Task& task) override;
    TaskResult ExecuteSync(const Task& task, 
                           std::chrono::milliseconds timeout) override;

    // ------------------------------------------------------------------------
    // Task Management
    // ------------------------------------------------------------------------
    
    bool CancelTask(const std::string& taskId) override;
    TaskStatus GetTaskStatus(const std::string& taskId) override;
    std::optional<TaskResult> GetTaskResult(const std::string& taskId) override;
    bool WaitForTask(const std::string& taskId, 
                     std::chrono::milliseconds timeout) override;

    // ------------------------------------------------------------------------
    // Task Queries
    // ------------------------------------------------------------------------
    
    size_t GetPendingCount() const override;
    size_t GetRunningCount() const override;
    size_t GetTotalTaskCount() const override;
    std::vector<std::string> GetActiveTaskIds() const override;
    std::optional<Task> GetTaskInfo(const std::string& taskId) override;

    // ------------------------------------------------------------------------
    // Event Registration
    // ------------------------------------------------------------------------
    
    int OnTaskStart(TaskStartCallback callback) override;
    int OnTaskComplete(TaskCompleteCallback callback) override;
    void UnregisterCallback(int callbackId) override;

    // ------------------------------------------------------------------------
    // Subsystem Access
    // ------------------------------------------------------------------------
    
    TaskScheduler& GetScheduler() override;
    ToolRegistry& GetToolRegistry() override;
    HistoryRecorder& GetHistory() override;
    PolicyEngine& GetPolicies() override;
    SubAgentManager& GetSubAgentManager() override;
    void SetInferenceEngine(
        std::shared_ptr<Inference::InferenceEngine> engine) override;
    std::shared_ptr<Inference::InferenceEngine> GetInferenceEngine() override;

    // ------------------------------------------------------------------------
    // Convenience Methods
    // ------------------------------------------------------------------------
    
    std::string ReadFile(const std::string& path) override;
    bool WriteFile(const std::string& path, const std::string& content) override;
    std::string ExecuteCommand(const std::string& command) override;
    std::string SearchCodebase(const std::string& query) override;
    std::string Generate(const std::string& prompt) override;

    // ------------------------------------------------------------------------
    // Diagnostics
    // ------------------------------------------------------------------------
    
    CoreStats GetStats() const override;
    void ResetStats() override;
    std::string GetLastError() const override;
    bool ValidateConfig() const override;

    // ------------------------------------------------------------------------
    // Legacy Access (for gradual migration)
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get the underlying legacy engine
     * @return Legacy engine pointer (may be null if not set)
     */
    AgenticEngine* GetLegacyEngine() const;

private:
    // Private implementation
    class Impl;
    std::unique_ptr<Impl> m_impl;

    // Private constructor - use Create() factory method
    LegacyCoreAdapter(AgenticEngine* legacyEngine, const CoreConfig& config);
};

} // namespace Agentic
} // namespace RawrXD
