// ============================================================================
// AgentRun.hpp — Per-Run Agent Execution State Machine
// ============================================================================
// Encapsulates a single autonomous agent execution with:
//   - ToolBudget + TurnBudget ownership (per-run, not global)
//   - Structured tool-call/result protocol
//   - State machine: Idle → Running → (Complete | Error | Cancelled | BudgetExhausted)
//   - Failure recovery: retry, timeout, cancellation propagation
//   - Trace/observability: every step recorded
//
// Replaces the raw maxAgentIterations integer with a full runtime.
//
// Pattern: PatchResult-style, no exceptions, thread-safe.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#pragma once

#include "AgentBudget.hpp"
#include "ToolCallResult.h"
#include "AgentTranscript.h"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <chrono>
#include <mutex>
#include <memory>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Forward declarations
// ============================================================================
class ToolDispatcher;

// ============================================================================
// Agent run termination reason
// ============================================================================
enum class AgentTerminationReason {
    Success,            // Task completed normally
    Failure,            // Unrecoverable error
    Cancelled,          // User or system cancelled
    Timeout,            // Deadline exceeded
    BudgetExhausted,    // Tool or turn budget hit zero
    ContextExhausted,   // Context window overflow
    StepLimitReached,   // Legacy: max steps reached
    WaitingForApproval  // Blocked on human approval gate
};

// ============================================================================
// Structured tool call envelope
// ============================================================================
struct ToolCall {
    std::string id;           // Unique call ID (UUID)
    std::string name;         // Tool name
    nlohmann::json arguments; // Parsed arguments
    std::string runId;        // Parent AgentRun ID
    uint32_t turnId;          // Which model turn emitted this
    uint32_t sequence;        // Sequence within the turn
    std::chrono::steady_clock::time_point createdAt;

    ToolCall() = default;
    ToolCall(const std::string& n, const nlohmann::json& a,
             const std::string& run, uint32_t turn, uint32_t seq);
};

// ============================================================================
// Structured tool result envelope
// ============================================================================
struct ToolResult {
    std::string callId;         // Matches ToolCall.id
    bool success;
    std::string output;         // stdout / structured output
    std::string error;          // stderr / error message
    int64_t durationMs;
    int exitCode;
    nlohmann::json metadata;    // Tool-specific metadata
    std::chrono::steady_clock::time_point completedAt;

    ToolResult() = default;
    explicit ToolResult(const ToolCallResult& tcr, const std::string& cid);
};

// ============================================================================
// Agent run configuration
// ============================================================================
struct AgentRunConfig {
    // Budgets
    uint32_t maxToolCalls       = 50;
    uint32_t toolExtensionSize  = 25;
    uint32_t maxToolExtensions  = 10;
    uint32_t toolHardCap        = 500;
    uint32_t maxTurns           = 100;
    uint32_t turnHardCap        = 500;

    // Timeouts
    uint32_t totalTimeoutSec    = 3600;     // Entire run
    uint32_t toolTimeoutSec     = 300;      // Per-tool invocation
    uint32_t modelTimeoutSec    = 120;      // Per-model response

    // Concurrency
    uint32_t maxConcurrentTools = 8;

    // Task classification
    TaskComplexity complexity   = TaskComplexity::Normal;

    // Flags
    bool dryRun                 = false;
    bool autoVerify             = true;
    bool requireApprovalForWrite = false;
    bool requireApprovalForExecute = true;

    // Paths
    std::string transcriptPath;
    std::string workingDirectory;
    std::string model;
    std::string ollamaBaseUrl = "";
};

// ============================================================================
// Agent run state
// ============================================================================
enum class AgentRunState {
    Idle,
    Running,
    WaitingForModel,
    ExecutingTools,
    Verifying,
    Complete,
    Error,
    Cancelled,
    BudgetExhausted,
    Timeout
};

// ============================================================================
// AgentRun — single autonomous execution context
// ============================================================================
class AgentRun {
public:
    AgentRun();
    explicit AgentRun(const AgentRunConfig& config);
    ~AgentRun();

    // ---- Configuration ----
    void Configure(const AgentRunConfig& config);
    const AgentRunConfig& GetConfig() const { return m_config; }

    // ---- Lifecycle ----
    void Start(const std::string& task);
    void Complete(AgentTerminationReason reason, const std::string& finalAnswer);
    void Cancel();
    void Fail(const std::string& error);

    // ---- Budget queries ----
    bool CanCallTool(uint32_t count = 1) const;
    bool CanTakeTurn() const;
    bool RequestToolExtension(uint32_t requested, uint32_t& grantedOut);
    const ToolBudget& GetToolBudget() const { return m_toolBudget; }
    const TurnBudget& GetTurnBudget() const { return m_turnBudget; }

    // ---- Tool accounting ----
    bool ConsumeToolCalls(uint32_t count = 1);
    bool ConsumeTurn();
    void RecordToolCall(const ToolCall& call);
    void RecordToolResult(const ToolResult& result);

    // ---- State ----
    AgentRunState GetState() const { return m_state.load(); }
    AgentTerminationReason GetTerminationReason() const { return m_termReason; }
    std::string GetRunId() const { return m_runId; }
    std::string GetFinalAnswer() const { return m_finalAnswer; }

    // ---- Time ----
    bool IsTimedOut() const;
    uint32_t GetElapsedSec() const;
    uint32_t GetRemainingSec() const;

    // ---- Transcript ----
    const AgentTranscript& GetTranscript() const { return m_transcript; }
    void SaveTranscript() const;

    // ---- Trace / observability ----
    std::string GetTraceSummary() const;
    uint32_t GetToolCallCount() const { return m_toolCallCount.load(); }
    uint32_t GetTurnCount() const { return m_turnCount.load(); }

    // ---- Callbacks ----
    using StateChangeCallback = std::function<void(AgentRunState oldState, AgentRunState newState)>;
    using BudgetExhaustedCallback = std::function<void(const AgentRun& run, bool isToolBudget)>;
    void SetStateChangeCallback(StateChangeCallback cb);
    void SetBudgetExhaustedCallback(BudgetExhaustedCallback cb);

private:
    void SetState(AgentRunState newState);
    void FireBudgetExhausted(bool isToolBudget);

    AgentRunConfig m_config;
    std::string m_runId;
    std::string m_task;
    std::string m_finalAnswer;
    std::string m_error;

    std::atomic<AgentRunState> m_state{AgentRunState::Idle};
    AgentTerminationReason m_termReason = AgentTerminationReason::Success;

    ToolBudget m_toolBudget;
    TurnBudget m_turnBudget;

    std::atomic<uint32_t> m_toolCallCount{0};
    std::atomic<uint32_t> m_turnCount{0};

    std::chrono::steady_clock::time_point m_startTime;
    std::chrono::steady_clock::time_point m_endTime;

    AgentTranscript m_transcript;

    mutable std::mutex m_mutex;
    StateChangeCallback m_stateCallback;
    BudgetExhaustedCallback m_budgetCallback;
};

} // namespace Agent
} // namespace RawrXD
