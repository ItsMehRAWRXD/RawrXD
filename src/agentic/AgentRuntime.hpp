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

namespace RawrXD {
namespace Agent {

// ============================================================================
// ToolBudget - Per-run budget tracking with policy enforcement
// ============================================================================
struct ToolBudget {
    // Current state
    uint32_t remaining = 0;
    uint32_t consumed = 0;
    uint32_t extensionCount = 0;
    
    // Configuration
    uint32_t initialLimit = 25;
    uint32_t extensionSize = 25;
    uint32_t maxExtensions = 10;
    uint32_t hardCap = 500;
    
    // Adaptive sizing
    enum class TaskSize {
        SIMPLE = 25,
        NORMAL = 50,
        LARGE = 100,
        REPOSITORY = 250,
        DEEP_AUTONOMOUS = 500
    };
    
    void SetTaskSize(TaskSize size) {
        initialLimit = static_cast<uint32_t>(size);
        remaining = initialLimit;
        consumed = 0;
        extensionCount = 0;
    }
    
    bool CanCall() const {
        return remaining > 0 && (consumed + remaining) <= hardCap;
    }
    
    bool Consume() {
        if (!CanCall()) return false;
        consumed++;
        remaining--;
        return true;
    }
    
    bool Extend(uint32_t requested) {
        if (extensionCount >= maxExtensions) return false;
        
        uint32_t newTotal = consumed + remaining + requested;
        if (newTotal > hardCap) {
            requested = hardCap - (consumed + remaining);
        }
        
        if (requested == 0) return false;
        
        remaining += requested;
        extensionCount++;
        return true;
    }
    
    uint32_t GetMaxPossibleCalls() const {
        return initialLimit + (maxExtensions * extensionSize);
    }
    
    float GetUtilization() const {
        uint32_t maxCalls = GetMaxPossibleCalls();
        return maxCalls > 0 ? static_cast<float>(consumed) / maxCalls : 0.0f;
    }
    
    nlohmann::json ToJson() const {
        return {
            {"remaining", remaining},
            {"consumed", consumed},
            {"extensionCount", extensionCount},
            {"initialLimit", initialLimit},
            {"hardCap", hardCap},
            {"utilization", GetUtilization()}
        };
    }
};

// ============================================================================
// TurnBudget - Model turn/iteration tracking
// ============================================================================
struct TurnBudget {
    uint32_t remaining = 0;
    uint32_t consumed = 0;
    uint32_t initialLimit = 100;
    uint32_t hardCap = 1000;
    
    bool CanContinue() const {
        return remaining > 0 && (consumed + remaining) <= hardCap;
    }
    
    bool ConsumeTurn() {
        if (!CanContinue()) return false;
        consumed++;
        remaining--;
        return true;
    }
    
    nlohmann::json ToJson() const {
        return {
            {"remaining", remaining},
            {"consumed", consumed},
            {"initialLimit", initialLimit},
            {"hardCap", hardCap}
        };
    }
};

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
// ToolCall - Structured tool invocation envelope
// ============================================================================
struct ToolCall {
    std::string id;                    // Unique call ID
    std::string name;                  // Tool name
    nlohmann::json arguments;            // Tool arguments
    std::string runId;                 // Parent run ID
    uint32_t turnId = 0;               // Turn number
    uint32_t sequence = 0;               // Sequence within turn
    std::chrono::steady_clock::time_point timestamp;
    
    ToolCall() = default;
    ToolCall(const std::string& toolName, const nlohmann::json& args, 
             const std::string& run, uint32_t turn, uint32_t seq)
        : id(GenerateId()), name(toolName), arguments(args), runId(run), 
          turnId(turn), sequence(seq), timestamp(std::chrono::steady_clock::now()) {}
    
    static std::string GenerateId() {
        static std::atomic<uint64_t> counter{0};
        return "tc_" + std::to_string(++counter);
    }
    
    nlohmann::json ToJson() const {
        return {
            {"id", id},
            {"name", name},
            {"arguments", arguments},
            {"runId", runId},
            {"turnId", turnId},
            {"sequence", sequence},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()}
        };
    }
};

// ============================================================================
// ToolResult - Structured tool result envelope
// ============================================================================
struct ToolResult {
    std::string callId;                // Matching ToolCall.id
    bool success = false;
    nlohmann::json output;               // Tool output
    std::string error;                 // Error message if failed
    std::chrono::milliseconds duration{0};
    int exitCode = 0;
    nlohmann::json metadata;             // Additional metadata
    std::chrono::steady_clock::time_point timestamp;
    
    ToolResult() = default;
    explicit ToolResult(const std::string& id) : callId(id), timestamp(std::chrono::steady_clock::now()) {}
    
    static ToolResult Success(const std::string& callId, const nlohmann::json& data) {
        ToolResult r(callId);
        r.success = true;
        r.output = data;
        return r;
    }
    
    static ToolResult Failure(const std::string& callId, const std::string& err, int code = -1) {
        ToolResult r(callId);
        r.success = false;
        r.error = err;
        r.exitCode = code;
        return r;
    }
    
    nlohmann::json ToJson() const {
        return {
            {"callId", callId},
            {"success", success},
            {"output", output},
            {"error", error},
            {"durationMs", duration.count()},
            {"exitCode", exitCode},
            {"metadata", metadata},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()}
        };
    }
};

// ============================================================================
// Permission Level
// ============================================================================
enum class PermissionLevel {
    SAFE,              // Automatic execution
    APPROVAL_REQUIRED, // Needs human approval
    BLOCKED            // Never execute
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
