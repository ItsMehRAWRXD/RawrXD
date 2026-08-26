// ============================================================================
// AgentRuntime.hpp - Autonomous Agent Execution Runtime
// ToolBudget, AgentRun, ToolDispatcher, and structured tool protocol
// Surpasses Cursor + GitHub Copilot reliability with Ollama-class performance
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <atomic>
#include <queue>
#include <functional>
#include <future>
#include <chrono>
#include <optional>
#include <variant>
#include <nlohmann/json.hpp>

// Include canonical definitions to avoid redefinition conflicts
#include "AgentBudget.hpp"
#include "AgentRun.hpp"

namespace RawrXD {
namespace Agent {

// ============================================================================
// ResourceBudget - CPU/time/memory/process tracking
// ============================================================================
struct ResourceBudget {
    std::chrono::seconds maxWallClockTime{3600};  // 1 hour default
    std::chrono::seconds maxCpuTime{1800};          // 30 min CPU
    size_t maxMemoryBytes = 8ull * 1024 * 1024 * 1024;  // 8GB
    uint32_t maxSubprocessCount = 32;
    size_t maxOutputBytes = 100 * 1024 * 1024;      // 100MB output
    uint32_t maxContextTokens = 128000;
    
    std::chrono::steady_clock::time_point startTime;
    std::atomic<size_t> currentMemoryBytes{0};
    std::atomic<uint32_t> activeSubprocesses{0};
    std::atomic<size_t> totalOutputBytes{0};
    std::atomic<uint32_t> currentContextTokens{0};
    
    void Start() {
        startTime = std::chrono::steady_clock::now();
    }
    
    bool CheckTimeBudget() const {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        return elapsed < maxWallClockTime;
    }
    
    bool CanAllocateMemory(size_t bytes) const {
        return currentMemoryBytes.load() + bytes <= maxMemoryBytes;
    }
    
    bool CanSpawnProcess() const {
        return activeSubprocesses.load() < maxSubprocessCount;
    }
    
    nlohmann::json ToJson() const {
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        return {
            {"elapsedSeconds", std::chrono::duration_cast<std::chrono::seconds>(elapsed).count()},
            {"maxWallClockSeconds", maxWallClockTime.count()},
            {"currentMemoryMB", currentMemoryBytes.load() / (1024 * 1024)},
            {"maxMemoryMB", maxMemoryBytes / (1024 * 1024)},
            {"activeSubprocesses", activeSubprocesses.load()},
            {"maxSubprocesses", maxSubprocessCount}
        };
    }
};

// ============================================================================
// Tool Registry Entry
// ============================================================================
struct ToolRegistryEntry {
    std::string name;
    std::string description;
    nlohmann::json schema;               // JSON schema for arguments
    std::function<ToolResult(const ToolCall&)> handler;
    PermissionLevel permission = PermissionLevel::SAFE;
    std::chrono::seconds timeout{30};
    float cost = 1.0f;                   // Budget cost per call
    bool parallelizable = true;
    bool requiresConfirmation = false;
    std::vector<std::string> requiredPermissions;  // READ, WRITE, EXECUTE, etc.
};

// ============================================================================
// Agent State Machine States
// ============================================================================
enum class AgentState {
    IDLE,
    THINKING,          // Model generating response
    TOOL_CALLS_READY,  // Model emitted tool calls
    EXECUTING_TOOLS,   // Tools running
    COLLECTING_RESULTS,// Waiting for tool results
    COMPLETED,         // Task done
    FAILED,            // Unrecoverable error
    CANCELLED,         // User cancelled
    BUDGET_EXHAUSTED,  // Out of tool/turn budget
    TIMEOUT,           // Hit time limit
    WAITING_APPROVAL   // Waiting for human approval
};

// ============================================================================
// AgentRun - Complete agent execution context
// ============================================================================
class AgentRun {
public:
    std::string runId;
    std::string task;
    AgentState state = AgentState::IDLE;
    
    // Budgets
    ToolBudget toolBudget;
    TurnBudget turnBudget;
    ResourceBudget resourceBudget;
    
    // Execution tracking
    uint32_t currentTurn = 0;
    uint32_t currentSequence = 0;
    std::vector<ToolCall> toolHistory;
    std::vector<ToolResult> resultHistory;
    std::vector<nlohmann::json> modelResponses;
    
    // Context management
    std::string workingDirectory;
    std::vector<std::string> changedFiles;
    std::vector<std::string> checkpointFiles;
    nlohmann::json persistentState;
    
    // Timing
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    
    AgentRun() = default;
    explicit AgentRun(const std::string& taskDescription);
    
    // State transitions
    void Start();
    void Complete();
    void Fail(const std::string& reason);
    void Cancel();
    void BudgetExhausted();
    
    // Budget checks
    bool CanExecuteTool() const;
    bool CanContinueTurn() const;
    bool CheckResourceBudgets() const;
    
    // History
    void RecordToolCall(const ToolCall& call);
    void RecordToolResult(const ToolResult& result);
    void RecordModelResponse(const nlohmann::json& response);
    
    // Context compaction
    void CompactContext();
    size_t EstimateContextTokens() const;
    
    // Serialization
    nlohmann::json ToJson() const;
    static std::optional<AgentRun> FromJson(const nlohmann::json& json);
    
    // Checkpoint/Resume
    bool SaveCheckpoint(const std::string& path) const;
    bool LoadCheckpoint(const std::string& path);
    
private:
    mutable std::mutex mutex_;
};

// ============================================================================
// ToolDispatcher - Centralized tool execution with budget enforcement
// ============================================================================
class ToolDispatcher {
public:
    ToolDispatcher();
    ~ToolDispatcher();
    
    // Registry
    void RegisterTool(const ToolRegistryEntry& entry);
    void UnregisterTool(const std::string& name);
    bool HasTool(const std::string& name) const;
    std::vector<std::string> GetToolNames() const;
    
    // Validation
    bool ValidateCall(const ToolCall& call, std::string& error) const;
    bool AuthorizeCall(const ToolCall& call, AgentRun& run, std::string& error) const;
    
    // Budget check
    bool CheckBudget(const ToolCall& call, AgentRun& run) const;
    
    // Execution
    ToolResult Execute(const ToolCall& call, AgentRun& run);
    std::vector<ToolResult> ExecuteBatch(const std::vector<ToolCall>& calls, AgentRun& run);
    
    // Async execution
    std::future<ToolResult> ExecuteAsync(const ToolCall& call, AgentRun& run);
    
    // Configuration
    void SetMaxConcurrency(uint32_t max) { maxConcurrency_ = max; }
    void SetDefaultTimeout(std::chrono::seconds timeout) { defaultTimeout_ = timeout; }
    
    // Stats
    struct Stats {
        uint64_t totalCalls = 0;
        uint64_t successfulCalls = 0;
        uint64_t failedCalls = 0;
        uint64_t budgetRejections = 0;
        uint64_t permissionRejections = 0;
        uint64_t timeoutCount = 0;
        std::chrono::milliseconds totalExecutionTime{0};
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    std::unordered_map<std::string, ToolRegistryEntry> registry_;
    mutable std::mutex registryMutex_;
    
    std::atomic<uint32_t> activeExecutions_{0};
    uint32_t maxConcurrency_ = 8;
    std::chrono::seconds defaultTimeout_{30};
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    ToolResult ExecuteInternal(const ToolCall& call, AgentRun& run);
    bool WaitForExecutionSlot(std::chrono::milliseconds timeout);
};

// ============================================================================
// AgentRuntime - Main agent execution orchestrator
// ============================================================================
class AgentRuntime {
public:
    AgentRuntime();
    ~AgentRuntime();
    
    // Configuration
    void SetModelPath(const std::string& path) { modelPath_ = path; }
    void SetSystemPrompt(const std::string& prompt) { systemPrompt_ = prompt; }
    
    // Tool registration
    ToolDispatcher& GetToolDispatcher() { return dispatcher_; }
    
    // Execution
    std::string StartAgent(const std::string& task);
    AgentState GetAgentState(const std::string& runId) const;
    bool CancelAgent(const std::string& runId);
    bool PauseAgent(const std::string& runId);
    bool ResumeAgent(const std::string& runId);
    bool ExtendBudget(const std::string& runId, uint32_t additionalTools);
    
    // Queries
    nlohmann::json GetAgentStatus(const std::string& runId) const;
    nlohmann::json GetAgentTrace(const std::string& runId) const;
    std::vector<std::string> GetActiveRuns() const;
    
    // Checkpoint/Resume
    bool SaveCheckpoint(const std::string& runId, const std::string& path);
    bool LoadCheckpoint(const std::string& path);
    
    // Deterministic mode
    void SetDeterministicMode(bool enable, uint32_t seed = 42) {
        deterministic_ = enable;
        seed_ = seed;
    }
    
    // CLI/API controls
    void SetMaxToolCalls(uint32_t max) { defaultToolBudget_.initialLimit = max; }
    void SetMaxTurns(uint32_t max) { defaultTurnBudget_.initialLimit = max; }
    void SetToolExtensionSize(uint32_t size) { defaultToolBudget_.extensionSize = size; }
    void SetMaxToolExtensions(uint32_t max) { defaultToolBudget_.maxExtensions = max; }
    void SetToolHardCap(uint32_t cap) { defaultToolBudget_.hardCap = cap; }
    void SetMaxConcurrentTools(uint32_t max) { dispatcher_.SetMaxConcurrency(max); }
    void SetAgentTimeout(std::chrono::seconds timeout) { agentTimeout_ = timeout; }
    
private:
    ToolDispatcher dispatcher_;
    std::unordered_map<std::string, std::unique_ptr<AgentRun>> activeRuns_;
    mutable std::mutex runsMutex_;
    
    std::string modelPath_;
    std::string systemPrompt_;
    
    ToolBudget defaultToolBudget_;
    TurnBudget defaultTurnBudget_;
    ResourceBudget defaultResourceBudget_;
    std::chrono::seconds agentTimeout_{3600};
    
    bool deterministic_ = false;
    uint32_t seed_ = 42;
    
    // Background processing
    std::atomic<bool> running_{false};
    std::thread processingThread_;
    void ProcessingLoop();
    
    // Model interaction
    nlohmann::json CallModel(const std::string& prompt, const std::vector<ToolResult>& observations);
    std::vector<ToolCall> ParseToolCalls(const nlohmann::json& modelResponse);
    bool IsTaskComplete(const nlohmann::json& modelResponse);
    
    // State machine
    void ProcessTurn(AgentRun& run);
    void ExecuteTools(AgentRun& run, const std::vector<ToolCall>& calls);
    void HandleCompletion(AgentRun& run);
    void HandleFailure(AgentRun& run, const std::string& reason);
};

// ============================================================================
// Convenience Functions
// ============================================================================
std::string AgentStateToString(AgentState state);
AgentState StringToAgentState(const std::string& str);

} // namespace Agent
} // namespace RawrXD
