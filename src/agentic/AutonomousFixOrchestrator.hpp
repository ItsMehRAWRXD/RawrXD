// ============================================================================
// AutonomousFixOrchestrator.hpp — Closed-Loop Autonomous Repair Engine
// ============================================================================
// Implements the AUTONOMOUS-FIX-001 milestone:
//   INIT → INDEX → BASELINE → DIAGNOSE → PLAN → PATCH → BUILD → TEST → VERIFY
//
// Architecture:
//   AgentOrchestrator
//     └── AutonomousFixOrchestrator
//           ├── ToolDispatcher (read/search/write/build/test/git)
//           ├── AgentRuntime (budget, timeout, checkpoint)
//           └── EvidenceLog (structured JSON audit trail)
//
// Rule: Agent proposes. Tools execute. Verification decides.
// ============================================================================

#pragma once

#include "ToolDispatcher.hpp"
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Agent {

// Forward declarations — full definitions come from AgentRun.hpp (via ToolDispatcher.hpp)
class AgentRuntime;
class ToolDispatcher;

// ============================================================================
// State machine for autonomous repair
// ============================================================================
enum class FixPhase {
    Idle,
    Init,
    Index,
    Baseline,
    Diagnose,
    Plan,
    Patch,
    Build,
    Test,
    Verify,
    Recovery,      // FAIL → DIAGNOSE retry
    Done,
    Error
};

const char* FixPhaseToString(FixPhase phase);

// ============================================================================
// Transition record — every state change is observable
// ============================================================================
struct FixTransition {
    FixPhase from;
    FixPhase to;
    std::string reason;
    std::chrono::steady_clock::time_point timestamp;
    nlohmann::json context;  // tool results, diagnostics, etc.

    FixTransition(FixPhase f, FixPhase t, const std::string& r, nlohmann::json ctx = {})
        : from(f), to(t), reason(r), timestamp(std::chrono::steady_clock::now()),
          context(std::move(ctx)) {}
};

// ============================================================================
// Evidence artifact — complete audit trail for a repair session
// ============================================================================
struct FixEvidence {
    std::string sessionId;
    std::string repositoryPath;
    std::string taskDescription;
    FixPhase finalPhase = FixPhase::Idle;
    bool success = false;
    uint32_t iterationCount = 0;
    uint32_t maxIterations = 5;
    std::vector<FixTransition> transitions;
    nlohmann::json diagnostics;
    nlohmann::json patchSummary;
    nlohmann::json buildResult;
    nlohmann::json testResult;
    std::chrono::milliseconds totalDuration{0};

    nlohmann::json ToJson() const;
    bool SaveToFile(const std::string& path) const;
};

// ============================================================================
// Configuration
// ============================================================================
struct AutonomousFixConfig {
    uint32_t maxIterations = 5;
    uint32_t maxToolCallsPerIteration = 25;
    std::chrono::seconds buildTimeout{300};
    std::chrono::seconds testTimeout{300};
    std::chrono::seconds totalTimeout{3600};
    bool autoCommit = false;
    bool verifyAfterPatch = true;
    std::string evidenceOutputDir = "./evidence";
    std::string baselineBranch = "autonomous-fix-baseline";
};

// ============================================================================
// Callbacks for observability
// ============================================================================
using PhaseTransitionCallback = std::function<void(const FixTransition&)>;
using ToolInvocationCallback = std::function<void(const ToolCall&, const ToolResult&)>;

// ============================================================================
// AutonomousFixOrchestrator — the closed loop
// ============================================================================
class AutonomousFixOrchestrator {
public:
    AutonomousFixOrchestrator();
    ~AutonomousFixOrchestrator();

    // ---- Lifecycle ----
    bool Initialize(AgentRuntime* runtime, ToolDispatcher* dispatcher);
    bool IsInitialized() const { return initialized_; }

    // ---- Configuration ----
    void SetConfig(const AutonomousFixConfig& config) { config_ = config; }
    const AutonomousFixConfig& GetConfig() const { return config_; }

    // ---- Main entry point ----
    // Returns complete evidence artifact.
    FixEvidence RunAutonomousFix(const std::string& repositoryPath,
                                   const std::string& taskDescription);

    // ---- State queries ----
    FixPhase GetCurrentPhase() const;
    const std::vector<FixTransition>& GetTransitions() const { return transitions_; }
    const FixEvidence& GetLastEvidence() const { return lastEvidence_; }

    // ---- Callbacks ----
    void RegisterPhaseCallback(PhaseTransitionCallback cb);
    void RegisterToolCallback(ToolInvocationCallback cb);

    // ---- Cancellation ----
    void RequestCancel() { cancelRequested_ = true; }
    bool IsCancelRequested() const { return cancelRequested_.load(); }

private:
    // ---- State machine steps ----
    FixPhase RunInit(const std::string& repoPath, const std::string& task);
    FixPhase RunIndex();
    FixPhase RunBaseline();
    FixPhase RunDiagnose();
    FixPhase RunPlan();
    FixPhase RunPatch();
    FixPhase RunBuild();
    FixPhase RunTest();
    FixPhase RunVerify();
    FixPhase RunRecovery();

    // ---- Tool helpers ----
    ToolResult InvokeTool(const std::string& toolName, const nlohmann::json& args);
    bool ToolSucceeded(const ToolResult& result) const;

    // ---- Transition logging ----
    void Transition(FixPhase from, FixPhase to, const std::string& reason,
                    nlohmann::json context = {});
    void NotifyPhaseChange(const FixTransition& t);
    void NotifyToolInvocation(const ToolCall& call, const ToolResult& result);

    // ---- Evidence building ----
    void FinalizeEvidence(bool success);

    AgentRuntime* runtime_ = nullptr;
    ToolDispatcher* dispatcher_ = nullptr;
    AutonomousFixConfig config_;

    std::atomic<bool> initialized_{false};
    std::atomic<bool> cancelRequested_{false};

    FixPhase currentPhase_ = FixPhase::Idle;
    std::vector<FixTransition> transitions_;
    FixEvidence lastEvidence_;

    std::string currentRepoPath_;
    std::string currentTask_;
    std::string currentSessionId_;
    uint32_t currentIteration_ = 0;

    std::vector<PhaseTransitionCallback> phaseCallbacks_;
    std::vector<ToolInvocationCallback> toolCallbacks_;
    mutable std::mutex mutex_;
};

} // namespace Agent
} // namespace RawrXD
