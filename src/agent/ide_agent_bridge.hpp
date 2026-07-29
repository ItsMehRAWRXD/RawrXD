<<<<<<< HEAD
/**
 * @file ide_agent_bridge.hpp
 * @brief Plugin interface connecting IDE UI to agent execution pipeline (Qt-free)
 */
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#pragma once

#include "model_invoker.hpp"
#include "action_executor.hpp"
<<<<<<< HEAD
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>

struct ExecutionPlan {
    std::string wish;
    nlohmann::json actions;
=======
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct ExecutionPlan {
    std::string wish;
    json actions;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string reasoning;
    int estimatedTimeMs = 0;
    std::string status;
};

class IDEAgentBridge {
public:
    IDEAgentBridge();
<<<<<<< HEAD
    virtual ~IDEAgentBridge() {
        m_isShuttingDown.store(true, std::memory_order_release);
        if (m_retryThread.joinable()) m_retryThread.join();
    }

    void initialize(const std::string& endpoint, const std::string& backend = "ollama", const std::string& apiKey = "");
    void setProjectRoot(const std::string& root);
    std::string projectRoot() const { return m_projectRoot; }
    void executeWish(const std::string& wish, bool requireApproval = true);
    void planWish(const std::string& wish);
    void approvePlan();
    void rejectPlan();
    void cancelExecution();
    bool isExecuting() const { return m_isExecuting; }
    ExecutionPlan currentPlan() const { return m_currentPlan; }
    nlohmann::json executionHistory() const { return m_executionHistory; }
    void setDryRunMode(bool enabled);
    void setStopOnError(bool stopOnError);

    /** Autonomous retry: on plan generation failure, retry up to maxRetries with exponential backoff */
    void setRetryPolicy(int maxRetries, int initialBackoffMs = 1000);

    // Callbacks (replace Qt signals)
    std::function<void(const std::string&)> onAgentThinkingStarted;
    std::function<void(const ExecutionPlan&)> onAgentGeneratedPlan;
    std::function<void(const ExecutionPlan&)> onPlanApprovalNeeded;
    std::function<void(int)> onAgentExecutionStarted;
    std::function<void(int, const std::string&, bool)> onAgentExecutionProgress;
    std::function<void(int, int, int)> onAgentProgressUpdated;
    std::function<void(const nlohmann::json&, int)> onAgentCompleted;
    std::function<void(const std::string&, bool)> onAgentError;
    std::function<void(const std::string&, const std::vector<std::string>&)> onUserInputRequested;
    std::function<void()> onExecutionCancelled;

protected:
    // Event handlers (replace Qt slots)
    void onPlanGenerated(const LLMResponse& response);
    void onActionCompleted(int index, bool success, const nlohmann::json& result);
    void onActionFailed(int index, const std::string& error, bool recoverable);
    void onPlanCompleted(bool success, const nlohmann::json& result);
    void onUserInputNeeded(const std::string& query, const std::vector<std::string>& options);

    std::string buildExecutionContext() const;
    ExecutionPlan convertToExecutionPlan(const nlohmann::json& llmPlan);
    void executeCurrentPlan();
    void recordExecution(const std::string& wish, bool success, const nlohmann::json& result, int elapsedMs);

    std::unique_ptr<ModelInvoker> m_invoker;
    std::unique_ptr<ActionExecutor> m_executor;
=======
    ~IDEAgentBridge();

    // No copy
    IDEAgentBridge(const IDEAgentBridge&) = delete;
    IDEAgentBridge& operator=(const IDEAgentBridge&) = delete;

    void initialize(const std::string& endpoint, const std::string& backend, const std::string& apiKey);
    void setProjectRoot(const std::string& root);
    
    void executeWish(const std::string& wish, bool requireApproval);
    void planWish(const std::string& wish);
    void cancelExecution();
    void approveExecution();
    void rejectExecution();
    
    // Explicit Logic: New Code Completion API
    std::string generateCodeCompletion(const std::string& context, const std::string& prefix);

    void setDryRun(bool dryRun);

    // Callbacks to replace Signals
    std::function<void(const std::string& msg)> onAgentThinkingStarted;
    std::function<void(const std::string& planJson)> onPlanGenerated;
    std::function<void(const std::string& error, bool retryable)> onAgentError;
    std::function<void(int step, int total, const std::string& desc)> onProgressUpdated;
    std::function<void(const std::string& result)> onExecutionComplete;
    std::function<void(const std::string& planJson)> onApprovalRequested;

    // Accessors for derived classes and integration
    ModelInvoker* getModelInvoker() const { return m_invoker.get(); }
    ActionExecutor* getActionExecutor() const { return m_executor.get(); }

private:
    std::unique_ptr<ModelInvoker> m_invoker;
    std::unique_ptr<ActionExecutor> m_executor;
    
    std::string m_projectRoot;
    std::string m_lastPlanJson;
    bool m_requireApproval = false;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    bool m_isExecuting = false;
    bool m_dryRun = false;
<<<<<<< HEAD
    std::string m_projectRoot;
    ExecutionPlan m_currentPlan;
    nlohmann::json m_executionHistory = nlohmann::json::array();
    int m_executionStartTime = 0;
    bool m_requireApproval = true;
    bool m_stopOnError = true;

    int m_maxRetries = 0;
    int m_retryBackoffMs = 1000;
    int m_retriesLeft = 0;
    int m_currentRetryBackoffMs = 1000;
    InvocationParams m_lastParams;
    std::thread m_retryThread;
    std::atomic<bool> m_isShuttingDown{false};
    void retryPlanGeneration();
=======

    // Helper to build context
    json buildExecutionContext();
    
    // Handlers
    void handlePlanGenerated(const LLMResponse& response);
    void handleExecutionResult(bool success, const std::string& result);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
