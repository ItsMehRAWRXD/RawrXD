// ============================================================================
// File: src/agent/delegated_agents.hpp
//
// Purpose: Delegated Agent Lifecycle Management
// Resource quotas, cross-agent communication, task delegation protocol
//
// Production-ready implementation. No stubs.
//
// Design principles:
//   - Explicit delegation contract between parent and child agents
//   - Hard resource quotas with cooperative accounting
//   - Message bus for cross-agent communication
//   - Max delegation depth to prevent infinite recursion
//   - Full observability of every lifecycle transition
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace Delegation {

// ============================================================================
// Resource Quotas
// ============================================================================

struct ResourceLimits {
    int64_t maxTokens = 100000;          // total token budget
    int64_t maxWallTimeMs = 300000;      // 5 minutes
    int64_t maxCpuTimeMs = 120000;       // 2 minutes
    int64_t maxMemoryBytes = 512 * 1024 * 1024;  // 512 MiB
    int maxFileEdits = 50;               // number of file edits
    int maxSubProcesses = 4;             // spawned subprocesses
    int maxToolCalls = 100;              // tool invocations
    int maxSubAgents = 8;                // can spawn this many children
    double maxCostUsd = 0.0;             // 0 = unlimited (local models)

    bool isValid() const {
        return maxTokens > 0 && maxWallTimeMs > 0 && maxCpuTimeMs > 0 &&
               maxMemoryBytes > 0 && maxFileEdits >= 0 && maxSubProcesses >= 0 &&
               maxToolCalls >= 0 && maxSubAgents >= 0 && maxCostUsd >= 0.0;
    }
};

struct ResourceUsage {
    int64_t tokensUsed = 0;
    int64_t wallTimeMs = 0;
    int64_t cpuTimeMs = 0;
    int64_t memoryBytes = 0;
    int fileEdits = 0;
    int subProcesses = 0;
    int toolCalls = 0;
    int subAgents = 0;
    double costUsd = 0.0;

    bool within(const ResourceLimits& limits) const {
        return tokensUsed <= limits.maxTokens &&
               wallTimeMs <= limits.maxWallTimeMs &&
               cpuTimeMs <= limits.maxCpuTimeMs &&
               memoryBytes <= limits.maxMemoryBytes &&
               fileEdits <= limits.maxFileEdits &&
               subProcesses <= limits.maxSubProcesses &&
               toolCalls <= limits.maxToolCalls &&
               subAgents <= limits.maxSubAgents &&
               (limits.maxCostUsd <= 0.0 || costUsd <= limits.maxCostUsd);
    }

    // Which limit was exceeded (empty if within)
    std::string violatedLimit(const ResourceLimits& limits) const {
        if (tokensUsed > limits.maxTokens) return "maxTokens";
        if (wallTimeMs > limits.maxWallTimeMs) return "maxWallTimeMs";
        if (cpuTimeMs > limits.maxCpuTimeMs) return "maxCpuTimeMs";
        if (memoryBytes > limits.maxMemoryBytes) return "maxMemoryBytes";
        if (fileEdits > limits.maxFileEdits) return "maxFileEdits";
        if (subProcesses > limits.maxSubProcesses) return "maxSubProcesses";
        if (toolCalls > limits.maxToolCalls) return "maxToolCalls";
        if (subAgents > limits.maxSubAgents) return "maxSubAgents";
        if (limits.maxCostUsd > 0.0 && costUsd > limits.maxCostUsd) return "maxCostUsd";
        return "";
    }

    // Fraction (0-1+) of a limit consumed. >1 means exceeded.
    double fraction(const ResourceLimits& limits) const {
        double f = 0.0;
        auto upd = [&](double v) { if (v > f) f = v; };
        upd(static_cast<double>(tokensUsed) / limits.maxTokens);
        upd(static_cast<double>(wallTimeMs) / limits.maxWallTimeMs);
        upd(static_cast<double>(cpuTimeMs) / limits.maxCpuTimeMs);
        upd(static_cast<double>(memoryBytes) / limits.maxMemoryBytes);
        upd(static_cast<double>(fileEdits) / limits.maxFileEdits);
        upd(static_cast<double>(subProcesses) / limits.maxSubProcesses);
        upd(static_cast<double>(toolCalls) / limits.maxToolCalls);
        upd(static_cast<double>(subAgents) / limits.maxSubAgents);
        if (limits.maxCostUsd > 0.0) upd(costUsd / limits.maxCostUsd);
        return f;
    }

    // A limit of exactly zero means the resource is FORBIDDEN (zero budget),
    // not merely unused. Usage cannot exceed 0 without a call, so the plain
    // exceeded check never fires; this makes zero budgets explicit.
    static bool limitIsForbidden(int64_t limit)  { return limit == 0; }
    static bool limitIsForbidden(int limit)      { return limit == 0; }

    // Returns the name of the first zero-budget (forbidden) resource, else "".
    // Ignores maxCostUsd (0 legitimately means "unlimited cost").
    std::string forbiddenResource(const ResourceLimits& limits) const {
        if (limitIsForbidden(limits.maxTokens))      return "maxTokens";
        if (limitIsForbidden(limits.maxWallTimeMs))  return "maxWallTimeMs";
        if (limitIsForbidden(limits.maxCpuTimeMs))   return "maxCpuTimeMs";
        if (limitIsForbidden(limits.maxMemoryBytes)) return "maxMemoryBytes";
        if (limitIsForbidden(limits.maxFileEdits))   return "maxFileEdits";
        if (limitIsForbidden(limits.maxSubProcesses))return "maxSubProcesses";
        if (limitIsForbidden(limits.maxToolCalls))   return "maxToolCalls";
        if (limitIsForbidden(limits.maxSubAgents))   return "maxSubAgents";
        return "";
    }
};

// ============================================================================
// Task Specification & Result
// ============================================================================

struct DelegatedTask {
    std::string taskId;
    std::string parentAgentId;         // who delegated (empty = human/root)
    std::string title;
    std::string prompt;                 // instruction for the agent
    std::string deliverable;           // expected output description

    // Execution context
    std::vector<std::string> allowedTools;
    std::vector<std::string> fileScope;    // paths the agent may touch
    ResourceLimits limits;

    // Priority: higher runs first when agents contend
    int priority = 50;

    // Deadline
    int64_t deadlineMs = 0;            // 0 = none

    // Metadata
    std::unordered_map<std::string, std::string> metadata;

    int64_t createdAt = 0;

    DelegatedTask() = default;
    explicit DelegatedTask(std::string t, std::string p)
        : title(std::move(t)), prompt(std::move(p)) {}
};

struct DelegatedResult {
    std::string taskId;
    std::string agentId;
    bool success = false;
    std::string output;                 // final answer / artifact
    std::string errorMessage;
    ResourceUsage usage;
    int64_t startedAt = 0;
    int64_t completedAt = 0;
    std::vector<std::string> artifacts;   // files created/modified

    int64_t elapsedMs() const { return completedAt > startedAt ? completedAt - startedAt : 0; }

    // Human-readable outcome
    std::string toJSON() const;
};

// ============================================================================
// Agent Capabilities
// ============================================================================

enum class AgentCapability {
    CodeEdit,           // can edit source files
    BuildAndTest,       // can run build/test pipelines
    Research,           // can read/search (read-only)
    Git,                // can perform git operations
    Planning,           // can decompose tasks and delegate
    Verification,       // can validate outputs
    Docs                // can write documentation
};

inline const char* capabilityName(AgentCapability c) {
    switch (c) {
        case AgentCapability::CodeEdit:      return "code_edit";
        case AgentCapability::BuildAndTest:  return "build_and_test";
        case AgentCapability::Research:      return "research";
        case AgentCapability::Git:           return "git";
        case AgentCapability::Planning:      return "planning";
        case AgentCapability::Verification:  return "verification";
        case AgentCapability::Docs:          return "docs";
    }
    return "unknown";
}

// ============================================================================
// DelegatedAgent
// ============================================================================

enum class AgentState {
    Created,       // constructed, not started
    Queued,        // waiting for an execution slot
    Running,       // actively executing
    Paused,        // suspended (cooperative checkpoint)
    Completed,     // finished successfully
    Failed,        // finished with error
    Cancelled,     // terminated by parent/user
    TimedOut       // exceeded wall time limit
};

inline const char* stateName(AgentState s) {
    switch (s) {
        case AgentState::Created:    return "created";
        case AgentState::Queued:     return "queued";
        case AgentState::Running:    return "running";
        case AgentState::Paused:     return "paused";
        case AgentState::Completed:  return "completed";
        case AgentState::Failed:     return "failed";
        case AgentState::Cancelled:  return "cancelled";
        case AgentState::TimedOut:   return "timed_out";
    }
    return "unknown";
}

struct DelegatedAgent {
    std::string agentId;
    std::string label;                  // short human-readable name
    std::string parentAgentId;          // "" for root
    int depth = 0;                      // delegation depth

    std::vector<AgentCapability> capabilities;
    ResourceLimits limits;
    ResourceUsage usage;

    AgentState state = AgentState::Created;

    DelegatedTask currentTask;
    bool hasTask = false;

    int64_t createdAt = 0;
    int64_t startedAt = 0;
    int64_t finishedAt = 0;

    std::string lastError;
    int tasksCompleted = 0;
    int tasksFailed = 0;

    // Cooperative cancellation token
    std::shared_ptr<std::atomic<bool>> cancelToken;

    DelegatedAgent() = default;
    explicit DelegatedAgent(std::string id, std::string lbl)
        : agentId(std::move(id)), label(std::move(lbl)) {}

    bool isTerminal() const {
        return state == AgentState::Completed || state == AgentState::Failed ||
               state == AgentState::Cancelled || state == AgentState::TimedOut;
    }

    bool hasCapability(AgentCapability c) const {
        for (auto cap : capabilities) if (cap == c) return true;
        return false;
    }

    double limitFraction() const { return usage.fraction(limits); }

    std::string stateString() const { return stateName(state); }
};

// ============================================================================
// AgentMessage — cross-agent communication
// ============================================================================

struct AgentMessage {
    std::string messageId;
    std::string fromAgentId;            // "" = parent/human
    std::string toAgentId;              // "" = broadcast to all
    std::string kind;                   // "request", "response", "event", "error"

    std::string subject;
    std::string body;

    // Correlation for request/response pairs
    std::string correlationId;
    std::string inReplyTo;

    int64_t sentAt = 0;
    int64_t deliveredAt = 0;

    AgentMessage() = default;
};

// ============================================================================
// DelegationManager
// ============================================================================

class DelegationManager {
public:
    using AgentWorkFn = std::function<std::string(DelegatedAgent& agent, const DelegatedTask& task)>;
    using EventCallback = std::function<void(const std::string& agentId, AgentState newState)>;
    using MessageCallback = std::function<void(const AgentMessage& message)>;

    struct Config {
        int maxConcurrentAgents = 8;
        int maxDelegationDepth = 4;
        ResourceLimits defaultLimits;
        bool enforceQuotas = true;
        bool autoStart = true;          // start agents immediately on delegate()
        std::string logPath;            // JSONL delegation audit log
    };

    explicit DelegationManager(const Config& config = Config{});
    ~DelegationManager();

    // ---- Configuration ----
    void setConfig(const Config& config);
    Config getConfig() const;

    // The function that actually performs an agent's work. In production this
    // drives the agentic engine; it is injectable so the manager is testable.
    void setAgentWorkFn(AgentWorkFn fn);

    // ---- Agent Lifecycle ----
    std::string createAgent(const std::string& label,
                            const std::vector<AgentCapability>& capabilities,
                            const ResourceLimits& limits = ResourceLimits{},
                            const std::string& parentAgentId = "");

    bool removeAgent(const std::string& agentId);
    void removeAll();

    DelegatedAgent* getAgent(const std::string& agentId);
    std::vector<DelegatedAgent> getAllAgents() const;

    // ---- Delegation ----
    // Delegate a task to a new or existing agent. Returns taskId ("" on refusal).
    std::string delegate(const DelegatedTask& task, const std::string& toAgentId = "");
    std::string delegateToNew(const DelegatedTask& task,
                              const std::string& label,
                              const std::vector<AgentCapability>& capabilities,
                              const ResourceLimits& limits);

    // Wait for a task result (blocking)
    DelegatedResult waitForTask(const std::string& taskId, int timeoutMs = 300000);

    // ---- Cancellation ----
    bool cancelAgent(const std::string& agentId);
    void cancelAll();
    bool cancelTask(const std::string& taskId);

    // ---- Messaging ----
    bool sendMessage(const AgentMessage& message);
    std::vector<AgentMessage> getMessagesFor(const std::string& agentId, bool undeliveredOnly = true) const;
    void ackMessages(const std::string& agentId);

    // Broadcast a message to all agents
    bool broadcast(const std::string& fromAgentId, const std::string& kind,
                   const std::string& subject, const std::string& body);

    // ---- Callbacks ----
    void onAgentStateChanged(EventCallback cb);
    void onMessage(MessageCallback cb);

    // ---- Status ----
    struct Stats {
        int activeAgents = 0;
        int totalAgentsCreated = 0;
        int totalTasksCompleted = 0;
        int totalTasksFailed = 0;
        int totalMessagesSent = 0;
        int queuedAgents = 0;
    };
    Stats getStats() const;

    std::string statusSummary() const;

    // Export full state as JSON (for IDE display / persistence)
    std::string exportStateJSON() const;

    // Blocking until all queued work finishes
    void waitForIdle(int timeoutMs = 300000);

private:
    struct PendingTask {
        DelegatedTask task;
        std::string agentId;
        std::string resultId;
        bool done = false;
        DelegatedResult result;
    };

    Config m_config;
    AgentWorkFn m_workFn;
    EventCallback m_stateCb;
    MessageCallback m_messageCb;

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::shared_ptr<DelegatedAgent>> m_agents;
    std::unordered_map<std::string, std::shared_ptr<PendingTask>> m_tasks;
    std::queue<std::string> m_readyQueue;    // agentIds ready to run
    std::vector<AgentMessage> m_messages;
    std::unordered_map<std::string, std::vector<size_t>> m_messageIndex; // agentId -> indices

    std::thread m_scheduler;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};
    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    std::condition_variable m_idleCv;

    std::atomic<int> m_activeAgents{0};
    std::atomic<int> m_totalCreated{0};
    std::atomic<int> m_totalCompleted{0};
    std::atomic<int> m_totalFailed{0};
    std::atomic<int> m_totalMessages{0};

    void schedulerLoop();
    void runAgent(const std::string& agentId);
    // Internal: assumes m_mutex is ALREADY held by the caller.
    std::string createAgentLocked(const std::string& label,
                                  const std::vector<AgentCapability>& capabilities,
                                  const ResourceLimits& limits,
                                  const std::string& parentAgentId);
    std::string makeId(const char* prefix) const;
    int64_t nowMs() const;
    void setAgentState(const std::shared_ptr<DelegatedAgent>& agent, AgentState newState);
    void auditLog(const std::string& json) const;
    bool wouldExceedDepth(const std::string& parentAgentId) const;
};

} // namespace Delegation
} // namespace RawrXD
